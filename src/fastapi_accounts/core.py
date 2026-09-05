import inspect
import logging
import os
from typing import Any, Callable, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from fastapi_accounts.adapters.sqlalchemy import SQLAlchemyAdapter
from fastapi_accounts.models.default import User
from fastapi_accounts.schemas.auth import (
    EmailVerificationRequest,
    LoginRequest,
    RegisterRequest,
    RequestVerificationEmailRequest,
    TokenResponse,
)
from fastapi_accounts.schemas.user import UserRead
from fastapi_accounts.security.tokens import TimedTokenSigner, generate_secure_token
from fastapi_accounts.transports.base import BaseTransport
from fastapi_accounts.transports.bearer import BearerTransport
from fastapi_accounts.transports.cookie import CookieTransport

logger = logging.getLogger("fastapi_accounts")


class FastAPIAccounts:
    """Core authentication and account management engine for FastAPI."""

    def __init__(
        self,
        adapter: SQLAlchemyAdapter,
        secret_key: str,
        transport: Optional[BaseTransport] = None,
        verify_email_required: bool = False,
        session_max_age_seconds: int = 86400 * 14,
        on_after_register: Optional[Callable[[User, str], Any]] = None,
    ):
        self.adapter = adapter
        
        # Resolve secret key from environment if prefixed with env:
        if secret_key.startswith("env:"):
            env_var = secret_key.split("env:", 1)[1]
            self.secret_key = os.environ.get(env_var, "")
            if not self.secret_key:
                raise ValueError(f"Environment variable '{env_var}' is not set.")
        else:
            self.secret_key = secret_key

        self.transport = transport or CookieTransport()
        self.verify_email_required = verify_email_required
        self.session_max_age_seconds = session_max_age_seconds
        self.on_after_register = on_after_register
        
        self.token_signer = TimedTokenSigner(self.secret_key)
        self.router = self._build_router()

    def generate_email_verification_token(self, email: str) -> str:
        """Generate a cryptographically signed verification token for an email address."""
        return self.token_signer.create_token({"email": email.strip().lower(), "action": "verify_email"})

    def verify_email_verification_token(self, token: str) -> Optional[str]:
        """Validate an email verification token and return the email if valid."""
        payload = self.token_signer.verify_token(token)
        if payload and payload.get("action") == "verify_email":
            return payload.get("email")
        return None

    async def _dispatch_verification_email(self, user: User, email: str, token: str) -> None:
        """Trigger developer-supplied callback or log token to console in development."""
        if self.on_after_register:
            if inspect.iscoroutinefunction(self.on_after_register):
                await self.on_after_register(user, token)
            else:
                self.on_after_register(user, token)
        else:
            logger.info(f"📨 [FastAPI Accounts] Verification token for '{email}': {token}")
            print(f"\n📨 [FastAPI Accounts] Verification link for '{email}': /api/v1/auth/verify-email with token: {token}\n")

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
            except ValueError as e:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

            verification_token = self.generate_email_verification_token(email_record.email)
            await self._dispatch_verification_email(user, email_record.email, verification_token)

            return user

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
                    if email_record.email == payload.email.strip().lower() and not email_record.is_verified:
                        token = self.generate_email_verification_token(email_record.email)
                        await self._dispatch_verification_email(user, email_record.email, token)
                        break

            # Always return a generic success message to prevent email enumeration
            return {"message": "If the email is registered and unverified, a verification link has been sent."}

        @router.post(
            "/login",
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

            # Set response headers or cookies based on transport
            self.transport.set_login_response(response, raw_session_token)

            if isinstance(self.transport, BearerTransport):
                return TokenResponse(access_token=raw_session_token, token_type="bearer")

            return user

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

            self.transport.set_logout_response(response)
            return {"message": "Logged out successfully."}

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
    ) -> Optional[User]:
        """Dependency that returns the current authenticated User, or None if unauthenticated."""
        # When called through FastAPI Depends(), retrieve session from adapter
        raw_token = self.transport.extract_token(request)
        if not raw_token:
            return None

        # Fetch db session from generator if not injected directly
        async with self.adapter.session_maker() as db_session:
            session_and_user = await self.adapter.get_session_and_user(db_session, raw_token)
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
                headers={"WWW-Authenticate": "Bearer"} if isinstance(self.transport, BearerTransport) else None,
            )
        return user

    async def current_superuser(
        self,
        user: User = Depends(lambda: None),
    ) -> User:
        """Dependency that returns the authenticated superuser, or raises 403 Forbidden."""
        if not user or not user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Superuser privileges are required.",
            )
        return user
