from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from fastapi_accounts.models.default import (
    EmailAddress,
    PasswordCredential,
    Session,
    User,
)


class UserStoreProtocol(Protocol):
    """Pure persistence port for accounts storage without business logic or hashing."""

    async def get_user_by_id(
        self, session: AsyncSession, user_id: uuid.UUID
    ) -> User | None: ...

    async def get_user_by_email(
        self, session: AsyncSession, email: str
    ) -> User | None: ...

    async def get_password_credential(
        self, session: AsyncSession, user_id: uuid.UUID
    ) -> PasswordCredential | None: ...

    async def create_user_with_password(
        self,
        session: AsyncSession,
        email: str,
        hashed_password: str,
        is_verified: bool = False,
        is_superuser: bool = False,
    ) -> tuple[User, EmailAddress]: ...

    async def verify_email(
        self, session: AsyncSession, email: str
    ) -> EmailAddress | None: ...

    async def create_session(
        self,
        session: AsyncSession,
        user_id: uuid.UUID,
        raw_token: str,
        max_age_seconds: int = 86400 * 14,
        expected_credential_version: int | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> Session: ...

    async def get_session_and_user(
        self, session: AsyncSession, raw_token: str
    ) -> tuple[Session, User] | None: ...

    async def revoke_session(self, session: AsyncSession, raw_token: str) -> bool: ...

    async def revoke_all_user_sessions(
        self, session: AsyncSession, user_id: uuid.UUID
    ) -> int: ...

    async def revoke_other_user_sessions(
        self, session: AsyncSession, user_id: uuid.UUID, current_raw_token: str
    ) -> int: ...

    async def update_password_if_version(
        self,
        session: AsyncSession,
        user_id: uuid.UUID,
        expected_version: int,
        new_hashed_password: str,
    ) -> bool: ...

    async def atomic_reset_password(
        self,
        session: AsyncSession,
        user_id: uuid.UUID,
        expected_cred_v: int,
        new_hashed_password: str,
    ) -> bool: ...
