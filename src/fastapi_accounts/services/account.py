from __future__ import annotations

import inspect
import logging
import uuid
from collections.abc import Callable
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from fastapi_accounts.schemas.principal import UserPrincipal
from fastapi_accounts.security.password import PasswordService
from fastapi_accounts.security.tokens import TimedTokenSigner, generate_secure_token
from fastapi_accounts.stores.base import UserStoreProtocol

logger = logging.getLogger("fastapi_accounts.account_service")


def _to_principal(
    user: Any,
    primary_email: str | None = None,
    is_verified: bool = False,
    email_record: Any | None = None,
) -> UserPrincipal:
    email_val = primary_email
    verified_val = is_verified
    email_id_val = None
    email_created_at_val = None

    if email_record is not None:
        email_val = getattr(email_record, "email", email_val)
        verified_val = getattr(email_record, "is_verified", verified_val)
        email_id_val = getattr(email_record, "id", None)
        email_created_at_val = getattr(email_record, "created_at", None)
    elif hasattr(user, "emails") and user.emails:
        primary_record = next(
            (e for e in user.emails if getattr(e, "is_primary", False)), user.emails[0]
        )
        email_val = primary_record.email
        verified_val = primary_record.is_verified
        email_id_val = primary_record.id
        email_created_at_val = primary_record.created_at

    return UserPrincipal(
        id=user.id,
        email=email_val,
        email_id=email_id_val,
        email_created_at=email_created_at_val,
        is_active=user.is_active,
        is_superuser=user.is_superuser,
        is_verified=verified_val,
        created_at=user.created_at,
        updated_at=user.updated_at,
    )


class AccountService:
    """Core domain service for user lifecycle and authentication use cases."""

    def __init__(
        self,
        store: UserStoreProtocol,
        password_service: PasswordService,
        token_signer: TimedTokenSigner,
        on_after_register: Callable[..., Any] | None = None,
        on_after_request_password_reset: Callable[..., Any] | None = None,
        on_delivery_failure: Callable[..., Any] | None = None,
        reset_password_token_max_age_seconds: int = 900,
        allow_legacy_tokens: bool = False,
    ):
        self.store = store
        self.password_service = password_service
        self.token_signer = token_signer
        self.on_after_register = on_after_register
        self.on_after_request_password_reset = on_after_request_password_reset
        self.on_delivery_failure = on_delivery_failure
        self.reset_password_token_max_age_seconds = reset_password_token_max_age_seconds
        self.allow_legacy_tokens = allow_legacy_tokens

    async def _invoke_callback_safely(
        self,
        callback: Callable[..., Any] | None,
        action: str,
        user: UserPrincipal,
        token: str,
    ) -> None:
        """Execute post-commit notifications safely, containing failures without masking commits."""
        if callback is None:
            logger.info(
                "Notification event for action='%s', user_id='%s'.", action, user.id
            )
            return

        try:
            res = callback(user, token)
            if inspect.isawaitable(res):
                await res
        except Exception as exc:
            logger.error(
                "Error executing callback for action='%s', user_id='%s': %s",
                action,
                user.id,
                type(exc).__name__,
            )
            if self.on_delivery_failure:
                try:
                    fail_res = self.on_delivery_failure(action, user, exc)
                    if inspect.isawaitable(fail_res):
                        await fail_res
                except Exception as hook_exc:
                    logger.error(
                        "Error in on_delivery_failure hook for user_id='%s': %s",
                        user.id,
                        type(hook_exc).__name__,
                    )

    def generate_email_verification_token(self, email: str) -> str:
        return self.token_signer.create_token(
            {"email": email.strip().lower(), "action": "verify_email"}
        )

    def generate_password_reset_token(
        self, user_id: uuid.UUID, email: str, credential_version: int
    ) -> str:
        return self.token_signer.create_token(
            {
                "sub": str(user_id),
                "email": email.strip().lower(),
                "action": "reset_password",
                "token_v": 2,
                "cred_v": int(credential_version),
            },
            max_age_seconds=self.reset_password_token_max_age_seconds,
        )

    async def register_user(
        self,
        session: AsyncSession,
        email: str,
        password: str,
        is_verified: bool = False,
        is_superuser: bool = False,
    ) -> tuple[UserPrincipal, str]:
        """Register a new user account, commit transaction, and invoke post-commit callback."""
        clean_email = email.strip().lower()
        # Compute password hash off-loop BEFORE DB transaction
        hashed_pwd = await self.password_service.async_hash_password(password)

        try:
            user, email_rec = await self.store.create_user_with_password(
                session=session,
                email=clean_email,
                hashed_password=hashed_pwd,
                is_verified=is_verified,
                is_superuser=is_superuser,
            )
            await session.commit()
            principal = _to_principal(
                user, clean_email, is_verified, email_record=email_rec
            )
        except Exception:
            await session.rollback()
            raise

        token = self.generate_email_verification_token(clean_email)
        await self._invoke_callback_safely(
            self.on_after_register, "register", principal, token
        )
        return principal, token

    async def authenticate_user(
        self, session: AsyncSession, email: str, password: str
    ) -> tuple[UserPrincipal | None, int | None]:
        """Verify user credentials with dummy hash equalization on non-existent users."""
        clean_email = email.strip().lower()
        user = await self.store.get_user_by_email(session, clean_email)
        if not user or not user.is_active:
            await self.password_service.async_verify_dummy_password(password)
            return None, None

        cred = await self.store.get_password_credential(session, user.id)
        if not cred:
            await self.password_service.async_verify_dummy_password(password)
            return None, None

        is_valid = await self.password_service.async_verify_password(
            password, cred.hashed_password
        )
        if not is_valid:
            return None, None

        cred_v = getattr(cred, "credential_version", 1)
        principal = _to_principal(user, clean_email)
        return principal, cred_v

    async def request_password_reset(
        self, session: AsyncSession, email: str
    ) -> tuple[UserPrincipal | None, str | None]:
        """Generate reset challenge and dispatch post-commit notification."""
        clean_email = email.strip().lower()
        user = await self.store.get_user_by_email(session, clean_email)
        if user and user.is_active:
            cred = await self.store.get_password_credential(session, user.id)
            cred_v = getattr(cred, "credential_version", 1) if cred else 1
            principal = _to_principal(user, clean_email)
            token = self.generate_password_reset_token(user.id, clean_email, cred_v)
            await self._invoke_callback_safely(
                self.on_after_request_password_reset, "password_reset", principal, token
            )
            return principal, token
        return None, None

    async def request_verify_email(
        self, session: AsyncSession, email: str
    ) -> tuple[UserPrincipal | None, str | None]:
        """Look up user by email and send verification token if unverified."""
        clean_email = email.strip().lower()
        user = await self.store.get_user_by_email(session, clean_email)
        if user and user.is_active:
            for email_rec in getattr(user, "emails", []):
                if email_rec.email == clean_email and not email_rec.is_verified:
                    principal = _to_principal(
                        user, clean_email, is_verified=False, email_record=email_rec
                    )
                    token = self.generate_email_verification_token(clean_email)
                    await self._invoke_callback_safely(
                        self.on_after_register, "request_verify_email", principal, token
                    )
                    return principal, token
        return None, None

    async def reset_password(
        self, session: AsyncSession, token: str, new_password: str
    ) -> bool:
        """Reset password using versioned token with atomic compare-and-swap update."""
        from fastapi_accounts.security.tokens import KeyKind

        payload, key_kind = self.token_signer.verify_token_with_kind(token)
        if (
            not payload
            or key_kind != KeyKind.DERIVED
            or payload.get("token_v") != 2
            or payload.get("action") != "reset_password"
            or "sub" not in payload
        ):
            return False

        try:
            user_id = uuid.UUID(payload["sub"])
        except (ValueError, KeyError):
            return False

        cred_v = payload.get("cred_v")
        if type(cred_v) is not int or cred_v < 1:
            return False

        # Compute hash off-loop BEFORE DB transaction
        new_hash = await self.password_service.async_hash_password(new_password)

        try:
            success = await self.store.atomic_reset_password(
                session=session,
                user_id=user_id,
                expected_cred_v=cred_v,
                new_hashed_password=new_hash,
            )
            if not success:
                await session.rollback()
                return False
            await session.commit()
            return True
        except Exception:
            await session.rollback()
            raise

    async def change_password(
        self,
        session: AsyncSession,
        user_id: uuid.UUID,
        current_password: str,
        new_password: str,
        current_raw_token: str | None = None,
        revoke_other_sessions: bool = True,
    ) -> bool:
        """Verify current password and atomically update to new password with session revocation."""
        cred = await self.store.get_password_credential(session, user_id)
        if not cred:
            return False

        is_valid = await self.password_service.async_verify_password(
            current_password, cred.hashed_password
        )
        if not is_valid:
            return False

        new_hash = await self.password_service.async_hash_password(new_password)

        try:
            new_version = cred.credential_version + 1
            success = await self.store.update_password_if_version(
                session=session,
                user_id=user_id,
                expected_version=cred.credential_version,
                new_hashed_password=new_hash,
            )
            if not success:
                await session.rollback()
                return False

            if current_raw_token:
                # Update current session generation
                updated = await self.store.update_session_credential_version(
                    session, current_raw_token, new_version
                )
                if not updated:
                    await session.rollback()
                    return False
                if revoke_other_sessions:
                    # Revoke other sessions
                    await self.store.revoke_other_user_sessions(
                        session, user_id, current_raw_token
                    )
                else:
                    # Keep other sessions alive by updating their credential generation to new_version
                    await self.store.update_all_user_sessions_credential_version(
                        session, user_id, new_version
                    )
            else:
                if revoke_other_sessions:
                    # Programmatic password change without session token context: revoke all
                    await self.store.revoke_all_user_sessions(session, user_id)
                else:
                    await self.store.update_all_user_sessions_credential_version(
                        session, user_id, new_version
                    )

            await session.commit()
            return True
        except Exception:
            await session.rollback()
            raise

    async def verify_email(
        self, session: AsyncSession, token: str
    ) -> UserPrincipal | None:
        """Validate email verification token and mark address verified."""
        from fastapi_accounts.security.tokens import KeyKind

        payload, key_kind = self.token_signer.verify_token_with_kind(token)
        if not payload or payload.get("action") != "verify_email":
            return None

        if key_kind == KeyKind.RAW_FALLBACK and not self.allow_legacy_tokens:
            return None

        email = payload.get("email")
        if not email:
            return None

        try:
            email_rec = await self.store.verify_email(session, email)
            if not email_rec:
                await session.rollback()
                return None
            await session.commit()

            user = await self.store.get_user_by_id(session, email_rec.user_id)
            if not user:
                return None
            return _to_principal(
                user, email_rec.email, is_verified=True, email_record=email_rec
            )
        except Exception:
            await session.rollback()
            raise

    async def create_session(
        self,
        session: AsyncSession,
        user_id: uuid.UUID,
        max_age_seconds: int = 86400 * 14,
        expected_credential_version: int | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[str, str]:
        """Issue new session record and return (raw_session_token, session_id)."""
        raw_token = generate_secure_token(32)
        try:
            session_rec = await self.store.create_session(
                session=session,
                user_id=user_id,
                raw_token=raw_token,
                max_age_seconds=max_age_seconds,
                expected_credential_version=expected_credential_version,
                ip_address=ip_address,
                user_agent=user_agent,
            )
            await session.commit()
            return raw_token, session_rec.id
        except Exception:
            await session.rollback()
            raise

    async def revoke_session(self, session: AsyncSession, raw_token: str) -> bool:
        """Revoke active session token."""
        try:
            success = await self.store.revoke_session(session, raw_token)
            await session.commit()
            return success
        except Exception:
            await session.rollback()
            raise

    async def get_principal_by_token(
        self, session: AsyncSession, raw_token: str
    ) -> tuple[UserPrincipal, str] | None:
        """Retrieve active principal and session ID for a session token."""
        res = await self.store.get_session_and_user(session, raw_token)
        if not res:
            return None
        session_rec, user = res
        return _to_principal(user), session_rec.id
