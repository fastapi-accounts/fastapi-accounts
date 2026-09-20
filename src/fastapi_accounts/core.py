from __future__ import annotations

import logging
import os
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from fastapi_accounts.adapters.sqlalchemy import SQLAlchemyAdapter
from fastapi_accounts.dependencies.auth import create_current_user_dependency
from fastapi_accounts.schemas.auth import (
    ChangePasswordRequest,
    EmailVerificationRequest,
    LoginRequest,
    RegisterRequest,
    RequestPasswordResetRequest,
    RequestVerificationEmailRequest,
    ResetPasswordRequest,
    TokenResponse,
)
from fastapi_accounts.schemas.principal import UserPrincipal
from fastapi_accounts.schemas.user import EmailAddressRead, UserRead
from fastapi_accounts.security.csrf import (
    CSRFContext,
    create_pre_auth_csrf_token,
    create_session_csrf_token,
    validate_csrf_token,
    validate_origin_header,
)
from fastapi_accounts.security.password import PasswordService
from fastapi_accounts.security.rate_limiter import (
    BaseRateLimiter,
    InMemorySlidingWindowLimiter,
    build_rate_limit_key,
    resolve_client_ip,
)
from fastapi_accounts.security.tokens import (
    TimedTokenSigner,
    derive_key,
)
from fastapi_accounts.services.account import AccountService
from fastapi_accounts.transports.base import BaseTransport
from fastapi_accounts.transports.bearer import BearerTransport
from fastapi_accounts.transports.cookie import CookieTransport

logger = logging.getLogger("fastapi_accounts")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _to_user_read(principal: UserPrincipal) -> UserRead:
    emails_list = []
    if principal.email:
        emails_list.append(
            EmailAddressRead(
                id=principal.email_id or principal.id,
                user_id=principal.id,
                email=principal.email,
                is_verified=principal.is_verified,
                is_primary=True,
                created_at=principal.email_created_at or principal.created_at or _now(),
            )
        )
    return UserRead(
        id=principal.id,
        primary_email=principal.email,
        is_active=principal.is_active,
        is_superuser=principal.is_superuser,
        created_at=principal.created_at or _now(),
        updated_at=principal.updated_at or _now(),
        emails=emails_list,
    )


class FastAPIAccounts:
    """Core authentication and account management engine for FastAPI."""

    def __init__(
        self,
        adapter: SQLAlchemyAdapter,
        secret_key: str | Sequence[str],
        transport: BaseTransport | None = None,
        verify_email_required: bool = False,
        session_max_age_seconds: int = 86400 * 14,
        reset_password_token_max_age_seconds: int = 900,
        argon2_concurrency: int = 4,
        rate_limiter: BaseRateLimiter | None = None,
        allowed_origins: list[str] | None = None,
        trusted_proxies: list[str] | None = None,
        debug: bool = False,
        on_after_register: Callable[..., Any] | None = None,
        on_after_request_password_reset: Callable[..., Any] | None = None,
        on_delivery_failure: Callable[..., Any] | None = None,
        allow_legacy_tokens: bool = False,
    ):
        self.adapter = adapter

        # Resolve secret key sequence
        raw_keys: list[str]
        if isinstance(secret_key, str):
            raw_keys = [secret_key]
        else:
            raw_keys = list(secret_key)

        resolved_keys: list[str] = []
        for k in raw_keys:
            if k.startswith("env:"):
                env_var = k.split("env:", 1)[1]
                val = os.environ.get(env_var, "")
                if not val:
                    raise ValueError(f"Environment variable '{env_var}' is not set.")
                resolved_keys.append(val)
            else:
                resolved_keys.append(k)

        self.secret_keys = resolved_keys
        self.transport = transport or CookieTransport()
        self.verify_email_required = verify_email_required
        self.session_max_age_seconds = session_max_age_seconds
        self.reset_password_token_max_age_seconds = reset_password_token_max_age_seconds
        self.argon2_concurrency = argon2_concurrency
        self.allowed_origins = allowed_origins
        self.trusted_proxies = trusted_proxies
        self.debug = debug
        self.allow_legacy_tokens = allow_legacy_tokens

        # Rate limiter setup
        self.rate_limiter = rate_limiter or InMemorySlidingWindowLimiter()
        self.login_rate_limit = (5, 60)
        self.register_rate_limit = (10, 3600)
        self.request_reset_rate_limit = (3, 300)
        self.reset_password_rate_limit = (5, 300)
        self.request_verify_rate_limit = (3, 300)
        self.verify_email_rate_limit = (10, 300)
        self.change_password_rate_limit = (5, 300)

        # Cryptographic signers & services
        self.token_signer = TimedTokenSigner(
            self.secret_keys, domain=b"fastapi-accounts-auth-token"
        )
        self.csrf_signing_key = derive_key(
            self.secret_keys[0], b"fastapi-accounts-csrf-token"
        )
        self.ratelimit_hmac_key = derive_key(
            self.secret_keys[0], b"fastapi-accounts-ratelimit-hash"
        )

        self.password_service = PasswordService(
            argon2_concurrency=self.argon2_concurrency
        )

        # Domain service layer
        self.service = AccountService(
            store=self.adapter,
            password_service=self.password_service,
            token_signer=self.token_signer,
            on_after_register=on_after_register,
            on_after_request_password_reset=on_after_request_password_reset,
            on_delivery_failure=on_delivery_failure,
            reset_password_token_max_age_seconds=self.reset_password_token_max_age_seconds,
            allow_legacy_tokens=self.allow_legacy_tokens,
        )

        # Request-scoped dependencies
        self.get_current_user = create_current_user_dependency(
            adapter=self.adapter,
            service=self.service,
            transport=self.transport,
            optional=True,
        )
        self.current_active_user = create_current_user_dependency(
            adapter=self.adapter,
            service=self.service,
            transport=self.transport,
            optional=False,
            superuser_required=False,
        )
        self.current_superuser = create_current_user_dependency(
            adapter=self.adapter,
            service=self.service,
            transport=self.transport,
            optional=False,
            superuser_required=True,
        )

        self.router = self._build_router()

    async def _enforce_rate_limit(
        self,
        action: str,
        identity: str | None,
        request: Request,
        max_reqs: int,
        window_sec: int,
    ) -> None:
        client_ip = resolve_client_ip(request, self.trusted_proxies)
        key = build_rate_limit_key(action, identity, client_ip, self.ratelimit_hmac_key)
        allowed, retry_after = await self.rate_limiter.check_rate_limit(
            key, max_reqs, window_sec
        )
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please try again later.",
                headers={"Retry-After": str(retry_after)},
            )

    def _enforce_csrf(
        self,
        request: Request,
        current_session_id: str | None = None,
        context: CSRFContext = CSRFContext.DUAL_MODE,
    ) -> None:
        if isinstance(self.transport, CookieTransport) and getattr(
            self.transport, "csrf_protect", True
        ):
            if not validate_origin_header(request, self.allowed_origins):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Cross-origin request rejected.",
                )
            cookie_token = request.cookies.get(self.transport.csrf_cookie_name)
            header_token = request.headers.get("x-csrf-token") or request.headers.get(
                "x-xsrf-token"
            )
            if not validate_csrf_token(
                cookie_token,
                header_token,
                current_session_id,
                self.csrf_signing_key,
                expected_context=context,
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="CSRF token missing or invalid.",
                )

    def _build_router(self) -> APIRouter:
        router = APIRouter()

        @router.get(
            "/csrf",
            summary="Bootstrap pre-authentication or session CSRF token",
        )
        async def get_csrf_token(
            request: Request,
            response: Response,
            db: AsyncSession = Depends(self.adapter.get_db),
        ) -> dict[str, str]:
            response.headers["Cache-Control"] = "no-store, private"
            raw_token = self.transport.extract_token(request)
            session_info = (
                await self.service.get_principal_by_token(db, raw_token)
                if raw_token
                else None
            )
            if session_info:
                _principal, session_id = session_info
                csrf_token = create_session_csrf_token(
                    session_id, self.csrf_signing_key
                )
            else:
                csrf_token = create_pre_auth_csrf_token(self.csrf_signing_key)

            if isinstance(self.transport, CookieTransport):
                self.transport.set_csrf_cookie(response, csrf_token)
            return {"csrf_token": csrf_token}

        @router.post(
            "/register",
            response_model=UserRead,
            status_code=status.HTTP_201_CREATED,
            summary="Register a new user account",
        )
        async def register(
            payload: RegisterRequest,
            request: Request,
            response: Response,
            db: AsyncSession = Depends(self.adapter.get_db),
        ):
            await self._enforce_rate_limit(
                "register", payload.email, request, *self.register_rate_limit
            )
            self._enforce_csrf(request, context=CSRFContext.PRE_AUTH)

            try:
                principal, _ = await self.service.register_user(
                    session=db,
                    email=payload.email,
                    password=payload.password,
                    is_verified=False,
                )
            except ValueError as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)
                )
            except IntegrityError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User with this email already exists.",
                )
            except SQLAlchemyError as e:
                logger.error("Database error during registration: %s", type(e).__name__)
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Database error during registration.",
                )

            return _to_user_read(principal)

        @router.post(
            "/verify-email",
            summary="Verify email address with verification token",
        )
        async def verify_email(
            payload: EmailVerificationRequest,
            request: Request,
            db: AsyncSession = Depends(self.adapter.get_db),
        ):
            await self._enforce_rate_limit(
                "verify_email", None, request, *self.verify_email_rate_limit
            )
            raw_token = self.transport.extract_token(request)
            current_sid = None
            if raw_token:
                session_info = await self.service.get_principal_by_token(db, raw_token)
                if session_info:
                    current_sid = session_info[1]

            self._enforce_csrf(
                request, current_session_id=current_sid, context=CSRFContext.DUAL_MODE
            )

            try:
                principal = await self.service.verify_email(db, payload.token)
                if not principal:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Invalid or expired verification token.",
                    )
            except HTTPException:
                raise
            except SQLAlchemyError as e:
                logger.error(
                    "Database error during email verification: %s", type(e).__name__
                )
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Database error during email verification.",
                )

            return {"message": "Email address verified successfully."}

        @router.post(
            "/request-verify-email",
            summary="Request a new email verification token",
        )
        async def request_verify_email(
            payload: RequestVerificationEmailRequest,
            request: Request,
            db: AsyncSession = Depends(self.adapter.get_db),
        ):
            await self._enforce_rate_limit(
                "request_verify_email",
                payload.email,
                request,
                *self.request_verify_rate_limit,
            )
            await self.service.request_verify_email(db, payload.email)
            return {
                "message": "If the email is registered and unverified, a verification link has been sent."
            }

        @router.post(
            "/request-password-reset",
            summary="Request a password reset token",
        )
        async def request_password_reset(
            payload: RequestPasswordResetRequest,
            request: Request,
            db: AsyncSession = Depends(self.adapter.get_db),
        ):
            await self._enforce_rate_limit(
                "request_password_reset",
                payload.email,
                request,
                *self.request_reset_rate_limit,
            )
            await self.service.request_password_reset(db, payload.email)
            return {
                "message": "If an account with that email exists, a password reset link has been sent."
            }

        @router.post(
            "/reset-password",
            summary="Reset user password with a reset token",
        )
        async def reset_password(
            payload: ResetPasswordRequest,
            request: Request,
            db: AsyncSession = Depends(self.adapter.get_db),
        ):
            await self._enforce_rate_limit(
                "reset_password", None, request, *self.reset_password_rate_limit
            )
            raw_token = self.transport.extract_token(request)
            current_sid = None
            if raw_token:
                session_info = await self.service.get_principal_by_token(db, raw_token)
                if session_info:
                    current_sid = session_info[1]

            self._enforce_csrf(
                request, current_session_id=current_sid, context=CSRFContext.DUAL_MODE
            )

            try:
                success = await self.service.reset_password(
                    db, payload.token, payload.new_password
                )
                if not success:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Invalid or expired password reset token.",
                    )
            except HTTPException:
                raise
            except SQLAlchemyError as e:
                logger.error(
                    "Database error during password reset: %s", type(e).__name__
                )
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Database error during password reset.",
                )

            return {"message": "Password has been reset successfully."}

        @router.post(
            "/login",
            response_model=UserRead | TokenResponse,
            summary="Authenticate with email and password",
        )
        async def login(
            payload: LoginRequest,
            request: Request,
            response: Response,
            db: AsyncSession = Depends(self.adapter.get_db),
        ):
            await self._enforce_rate_limit(
                "login", payload.email, request, *self.login_rate_limit
            )
            self._enforce_csrf(request, context=CSRFContext.PRE_AUTH)

            principal, _email_str = await self.service.authenticate_user(
                session=db, email=payload.email, password=payload.password
            )
            if not principal:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid email or password.",
                )

            if self.verify_email_required and not principal.is_verified:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Email verification is required before logging in.",
                )

            client_ip = request.client.host if request.client else None
            user_agent = request.headers.get("user-agent")

            try:
                raw_session_token, session_id = await self.service.create_session(
                    session=db,
                    user_id=principal.id,
                    max_age_seconds=self.session_max_age_seconds,
                    ip_address=client_ip,
                    user_agent=user_agent,
                )
            except SQLAlchemyError as e:
                logger.error(
                    "Database error during session creation: %s", type(e).__name__
                )
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Database error during authentication.",
                )

            self.transport.set_login_response(response, raw_session_token)

            if isinstance(self.transport, CookieTransport):
                # Issue authenticated session-bound CSRF token
                auth_csrf_token = create_session_csrf_token(
                    session_id, self.csrf_signing_key
                )
                self.transport.set_csrf_cookie(response, auth_csrf_token)

            if isinstance(self.transport, BearerTransport):
                return TokenResponse(
                    access_token=raw_session_token, token_type="bearer"
                )

            return _to_user_read(principal)

        @router.post(
            "/logout",
            summary="Revoke active session and log out",
        )
        async def logout(
            request: Request,
            response: Response,
            db: AsyncSession = Depends(self.adapter.get_db),
        ):
            raw_token = self.transport.extract_token(request)
            current_sid = None
            if raw_token:
                session_info = await self.service.get_principal_by_token(db, raw_token)
                if session_info:
                    current_sid = session_info[1]

            if isinstance(self.transport, CookieTransport) and current_sid:
                self._enforce_csrf(
                    request,
                    current_session_id=current_sid,
                    context=CSRFContext.LOGOUT,
                )

            if raw_token and current_sid:
                try:
                    await self.service.revoke_session(db, raw_token)
                except SQLAlchemyError as e:
                    logger.error("Database error during logout: %s", type(e).__name__)
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Database error during logout.",
                    )

            self.transport.set_logout_response(response)
            return {"message": "Logged out successfully."}

        @router.post(
            "/change-password",
            summary="Change password for authenticated user",
        )
        async def change_password(
            payload: ChangePasswordRequest,
            request: Request,
            user: UserPrincipal = Depends(self.current_active_user),
            db: AsyncSession = Depends(self.adapter.get_db),
        ):
            await self._enforce_rate_limit(
                "change_password",
                str(user.id),
                request,
                *self.change_password_rate_limit,
            )
            raw_token = self.transport.extract_token(request)
            current_sid = None
            if raw_token:
                session_info = await self.service.get_principal_by_token(db, raw_token)
                if session_info:
                    current_sid = session_info[1]

            if isinstance(self.transport, CookieTransport):
                self._enforce_csrf(
                    request,
                    current_session_id=current_sid,
                    context=CSRFContext.SESSION_BOUND,
                )

            try:
                success = await self.service.change_password(
                    session=db,
                    user_id=user.id,
                    current_password=payload.current_password,
                    new_password=payload.new_password,
                    current_raw_token=raw_token,
                    revoke_other_sessions=payload.revoke_other_sessions,
                )
                if not success:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Current password is incorrect.",
                    )
            except HTTPException:
                raise
            except SQLAlchemyError as e:
                logger.error(
                    "Database error during password change: %s", type(e).__name__
                )
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Database error during password change.",
                )

            return {"message": "Password changed successfully."}

        @router.get(
            "/me",
            response_model=UserRead,
            summary="Retrieve current authenticated user profile",
        )
        async def get_me(user: UserPrincipal = Depends(self.current_active_user)):
            return _to_user_read(user)

        return router
