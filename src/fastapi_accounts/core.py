import inspect
import logging
import os
import uuid
from collections.abc import Callable
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from fastapi_accounts.adapters.sqlalchemy import SQLAlchemyAdapter
from fastapi_accounts.models.default import User
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
from fastapi_accounts.schemas.user import UserRead
from fastapi_accounts.security.tokens import TimedTokenSigner, generate_secure_token
from fastapi_accounts.transports.base import BaseTransport
from fastapi_accounts.transports.bearer import BearerTransport
from fastapi_accounts.transports.cookie import CookieTransport

logger = logging.getLogger("fastapi_accounts")


def _get_pwd_state_ts(dt: datetime | None) -> int:
    """Return microsecond epoch integer for password state tracking."""
    if dt is None:
        return 0
    return int(dt.timestamp() * 1_000_000)


class FastAPIAccounts:
    """Core authentication and account management engine for FastAPI."""

    def __init__(
        self,
        adapter: SQLAlchemyAdapter,
        secret_key: str,
        transport: BaseTransport | None = None,
        verify_email_required: bool = False,
        session_max_age_seconds: int = 86400 * 14,
        reset_password_token_max_age_seconds: int = 900,
        debug: bool = False,
        on_after_register: Callable[[User, str], Any] | None = None,
        on_after_request_password_reset: Callable[[User, str], Any] | None = None,
    ):
        self.adapter = adapter

        # Resolve secret key from environment if prefixed with env:
        if secret_key.startswith("env:"):
            env_var = secret_key.split("env:", 1)[1]
            resolved_key = os.environ.get(env_var, "")
            if not resolved_key:
                raise ValueError(f"Environment variable '{env_var}' is not set.")
            self.secret_key = resolved_key
        else:
            self.secret_key = secret_key

        if not self.secret_key or len(self.secret_key) < 32:
            raise ValueError(
                "FastAPIAccounts secret_key must be a non-empty string of at least 32 characters (256 bits). "
                "Generate a secure key using `secrets.token_urlsafe(32)`."
            )

        self.transport = transport or CookieTransport()
        self.verify_email_required = verify_email_required
        self.session_max_age_seconds = session_max_age_seconds
        self.reset_password_token_max_age_seconds = reset_password_token_max_age_seconds
        self.debug = debug
        self.on_after_register = on_after_register
        self.on_after_request_password_reset = on_after_request_password_reset

        self.token_signer = TimedTokenSigner(self.secret_key)
        self.router = self._build_router()

    def generate_email_verification_token(self, email: str) -> str:
        """Generate a cryptographically signed verification token for an email address."""
        return self.token_signer.create_token(
            {"email": email.strip().lower(), "action": "verify_email"}
        )

    def verify_email_verification_token(self, token: str) -> str | None:
        """Validate an email verification token and return the email if valid."""
        payload = self.token_signer.verify_token(token)
        if payload and payload.get("action") == "verify_email":
            return payload.get("email")
        return None

    def generate_password_reset_token(
        self,
        user_id: uuid.UUID,
        email: str,
        pwd_ts: int | datetime | None = None,
    ) -> str:
        """Generate a cryptographically signed password reset token bound to current password state."""
        if isinstance(pwd_ts, datetime):
            ts_val = _get_pwd_state_ts(pwd_ts)
        elif isinstance(pwd_ts, int):
            ts_val = pwd_ts
        else:
            ts_val = 0

        return self.token_signer.create_token(
            {
                "sub": str(user_id),
                "email": email.strip().lower(),
                "action": "reset_password",
                "pwd_ts": ts_val,
            },
            max_age_seconds=self.reset_password_token_max_age_seconds,
        )

    def verify_password_reset_token(self, token: str) -> dict[str, Any] | None:
        """Validate a password reset token and return the payload if valid."""
        payload = self.token_signer.verify_token(token)
        if payload and payload.get("action") == "reset_password" and "sub" in payload:
            return payload
        return None

    async def _dispatch_verification_email(
        self, user: User, email: str, token: str
    ) -> None:
        """Trigger developer-supplied callback or log event in development/production."""
        if self.on_after_register:
            if inspect.iscoroutinefunction(self.on_after_register):
                await self.on_after_register(user, token)
            else:
                self.on_after_register(user, token)
        else:
            if self.debug:
                logger.debug(
                    f"📨 [FastAPI Accounts] Verification token generated for '{email}' (prefix: {token[:8]}...)"
                )
            else:
                logger.info(
                    f"📨 [FastAPI Accounts] Verification email requested for '{email}'."
                )

    async def _dispatch_password_reset_email(
        self, user: User, email: str, token: str
    ) -> None:
        """Trigger developer-supplied callback or log event."""
        if self.on_after_request_password_reset:
            if inspect.iscoroutinefunction(self.on_after_request_password_reset):
                await self.on_after_request_password_reset(user, token)
            else:
                self.on_after_request_password_reset(user, token)
        else:
            if self.debug:
                logger.debug(
                    f"🔑 [FastAPI Accounts] Password reset token generated for '{email}' (prefix: {token[:8]}...)"
                )
            else:
                logger.info(
                    f"🔑 [FastAPI Accounts] Password reset requested for '{email}'."
                )

    def _build_router(self) -> APIRouter:
        router = APIRouter()

        @router.post(
            "/register",
            response_model=UserRead,
            status_code=status.HTTP_201_CREATED,
            summary="Register a new user account",
        )
        async def register(
            payload: RegisterRequest,
            response: Response,
            db: AsyncSession = Depends(self.adapter.get_db),
        ):
            try:
                user, email_record = await self.adapter.create_user_with_password(
                    session=db,
                    email=payload.email,
                    password=payload.password,
                    is_verified=False,
                )
                await db.commit()
                await db.refresh(user)
            except ValueError as e:
                await db.rollback()
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)
                )
            except IntegrityError:
                await db.rollback()
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User with this email already exists.",
                )
            except SQLAlchemyError as e:
                await db.rollback()
                logger.error(f"Database error during registration: {e}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Database error during registration.",
                )

            verification_token = self.generate_email_verification_token(
                email_record.email
            )
            await self._dispatch_verification_email(
                user, email_record.email, verification_token
            )

            return UserRead.model_validate(user)

        @router.post(
            "/verify-email",
            summary="Verify email address with verification token",
        )
        async def verify_email(
            payload: EmailVerificationRequest,
            db: AsyncSession = Depends(self.adapter.get_db),
        ):
            email = self.verify_email_verification_token(payload.token)
            if not email:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid or expired verification token.",
                )

            email_record = await self.adapter.verify_email(db, email)
            if not email_record:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Email address not found.",
                )

            await db.commit()
            return {"message": "Email address verified successfully."}

        @router.post(
            "/request-verify-email",
            summary="Request a new email verification token",
        )
        async def request_verify_email(
            payload: RequestVerificationEmailRequest,
            db: AsyncSession = Depends(self.adapter.get_db),
        ):
            user = await self.adapter.get_user_by_email(db, payload.email)
            if user:
                for email_record in user.emails:
                    if (
                        email_record.email == payload.email.strip().lower()
                        and not email_record.is_verified
                    ):
                        token = self.generate_email_verification_token(
                            email_record.email
                        )
                        await self._dispatch_verification_email(
                            user, email_record.email, token
                        )
                        break

            # Always return a generic success message to prevent email enumeration
            return {
                "message": "If the email is registered and unverified, a verification link has been sent."
            }

        @router.post(
            "/request-password-reset",
            summary="Request a password reset token",
        )
        async def request_password_reset(
            payload: RequestPasswordResetRequest,
            db: AsyncSession = Depends(self.adapter.get_db),
        ):
            user = await self.adapter.get_user_by_email(db, payload.email)
            if user and user.is_active:
                cred = await self.adapter.get_password_credential(db, user.id)
                user_cred = getattr(user, "password_credential", None)
                if cred is not None and cred.password_updated_at is not None:
                    pwd_ts = _get_pwd_state_ts(cred.password_updated_at)
                elif (
                    user_cred is not None
                    and getattr(user_cred, "password_updated_at", None) is not None
                ):
                    pwd_ts = _get_pwd_state_ts(user_cred.password_updated_at)
                else:
                    pwd_ts = 0
                token = self.generate_password_reset_token(
                    user.id, payload.email, pwd_ts=pwd_ts
                )
                await self._dispatch_password_reset_email(user, payload.email, token)

            # Always return a generic success message to prevent email enumeration
            return {
                "message": "If an account with that email exists, a password reset link has been sent."
            }

        @router.post(
            "/reset-password",
            summary="Reset user password with a reset token",
        )
        async def reset_password(
            payload: ResetPasswordRequest,
            db: AsyncSession = Depends(self.adapter.get_db),
        ):
            token_data = self.verify_password_reset_token(payload.token)
            if not token_data:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid or expired password reset token.",
                )

            try:
                user_id = uuid.UUID(token_data["sub"])
            except (ValueError, KeyError):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid token payload.",
                )

            cred = await self.adapter.get_password_credential(db, user_id)
            if not cred:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User account not found.",
                )

            current_pwd_ts = _get_pwd_state_ts(cred.password_updated_at)
            token_pwd_ts = token_data.get("pwd_ts")
            # Enforce single-use: token must contain integer pwd_ts matching current password timestamp (fail closed)
            if (
                token_pwd_ts is None
                or not isinstance(token_pwd_ts, int)
                or token_pwd_ts == 0
                or token_pwd_ts != current_pwd_ts
            ):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid or expired password reset token.",
                )

            success = await self.adapter.update_user_password(
                session=db, user_id=user_id, new_password=payload.new_password
            )
            if not success:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User account not found.",
                )

            await db.commit()
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
            user = await self.adapter.authenticate_user(
                session=db, email=payload.email, password=payload.password
            )
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid email or password.",
                )

            if self.verify_email_required:
                # Check if user has at least one verified email
                has_verified = any(e.is_verified for e in user.emails)
                if not has_verified:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Email verification is required before logging in.",
                    )

            # Issue new session
            raw_session_token = generate_secure_token(32)
            client_ip = request.client.host if request.client else None
            user_agent = request.headers.get("user-agent")

            await self.adapter.create_session(
                session=db,
                user_id=user.id,
                raw_token=raw_session_token,
                max_age_seconds=self.session_max_age_seconds,
                ip_address=client_ip,
                user_agent=user_agent,
            )
            await db.commit()

            # Set response headers or cookies based on transport
            self.transport.set_login_response(response, raw_session_token)

            if isinstance(self.transport, BearerTransport):
                return TokenResponse(
                    access_token=raw_session_token, token_type="bearer"
                )

            return UserRead.model_validate(user)

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
            if raw_token:
                await self.adapter.revoke_session(db, raw_token)
                await db.commit()

            self.transport.set_logout_response(response)
            return {"message": "Logged out successfully."}

        @router.post(
            "/change-password",
            summary="Change password for authenticated user",
        )
        async def change_password(
            payload: ChangePasswordRequest,
            request: Request,
            user: User = Depends(self.current_active_user),
            db: AsyncSession = Depends(self.adapter.get_db),
        ):
            success = await self.adapter.verify_and_update_password(
                session=db,
                user_id=user.id,
                current_password=payload.current_password,
                new_password=payload.new_password,
            )
            if not success:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Current password is incorrect.",
                )
            if payload.revoke_other_sessions:
                raw_token = self.transport.extract_token(request)
                if raw_token:
                    await self.adapter.revoke_other_user_sessions(
                        db, user.id, raw_token
                    )
            await db.commit()
            return {"message": "Password changed successfully."}

        @router.get(
            "/me",
            response_model=UserRead,
            summary="Retrieve current authenticated user profile",
        )
        async def get_me(user: User = Depends(self.current_active_user)):
            return user

        return router

    async def get_current_user(
        self,
        request: Request,
        db: AsyncSession = Depends(lambda: None),
    ) -> User | None:
        """Dependency that returns the current authenticated User, or None if unauthenticated."""
        # When called through FastAPI Depends(), retrieve session from adapter
        raw_token = self.transport.extract_token(request)
        if not raw_token:
            return None

        # Fetch db session from generator if not injected directly
        async with self.adapter.session_maker() as db_session:
            session_and_user = await self.adapter.get_session_and_user(
                db_session, raw_token
            )
            if not session_and_user:
                return None
            return session_and_user[1]

    async def current_active_user(
        self,
        request: Request,
    ) -> User:
        """Dependency that returns the authenticated active user, or raises 401 Unauthorized."""
        user = await self.get_current_user(request)
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication credentials are required or invalid.",
                headers={"WWW-Authenticate": "Bearer"}
                if isinstance(self.transport, BearerTransport)
                else None,
            )
        return user

    async def current_superuser(
        self,
        request: Request,
    ) -> User:
        """Dependency that returns the authenticated superuser, or raises 403 Forbidden."""
        user = await self.current_active_user(request)
        if not user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Superuser privileges are required.",
            )
        return user
