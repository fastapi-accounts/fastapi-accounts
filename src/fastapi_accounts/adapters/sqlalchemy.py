from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from datetime import datetime, timedelta, timezone
from typing import Any

import sqlalchemy as sa
from sqlalchemy import CursorResult, delete, select, update
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from fastapi_accounts.models.default import (
    Base,
    EmailAddress,
    PasswordCredential,
    Session,
    User,
)
from fastapi_accounts.security.tokens import hash_token


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SQLAlchemyAdapter:
    """Async SQLAlchemy persistence store adapter for FastAPI Accounts."""

    def __init__(
        self,
        database_url: str | None = None,
        engine: AsyncEngine | None = None,
        session_maker: async_sessionmaker[AsyncSession] | None = None,
        user_model: type[User] = User,
        email_model: type[EmailAddress] = EmailAddress,
        credential_model: type[PasswordCredential] = PasswordCredential,
        session_model: type[Session] = Session,
    ):
        if session_maker:
            self.session_maker = session_maker
            self.engine = engine
        elif engine:
            self.engine = engine
            self.session_maker = async_sessionmaker(
                bind=self.engine, class_=AsyncSession, expire_on_commit=False
            )
        elif database_url:
            self.engine = create_async_engine(database_url, echo=False)
            self.session_maker = async_sessionmaker(
                bind=self.engine, class_=AsyncSession, expire_on_commit=False
            )
        else:
            raise ValueError(
                "Either database_url, engine, or session_maker must be provided to SQLAlchemyAdapter."
            )

        self.user_model = user_model
        self.email_model = email_model
        self.credential_model = credential_model
        self.session_model = session_model

    async def create_all(self) -> None:
        """Create database tables defined in Base metadata (useful for quickstarts and testing)."""
        if self.engine is None:
            raise RuntimeError("Engine is not available to create tables.")
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def get_db(self) -> AsyncGenerator[AsyncSession, None]:
        """FastAPI Dependency for yielding database sessions per request."""
        async with self.session_maker() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise

    async def get_user_by_email(self, session: AsyncSession, email: str) -> User | None:
        """Find user by email address (case-insensitive)."""
        clean_email = email.strip().lower()
        stmt = (
            select(self.user_model)
            .join(self.email_model, self.email_model.user_id == self.user_model.id)
            .where(self.email_model.email == clean_email)
        )
        result = await session.execute(stmt)
        return result.scalars().first()

    async def get_user_by_id(
        self, session: AsyncSession, user_id: uuid.UUID
    ) -> User | None:
        """Retrieve user by primary UUID."""
        stmt = select(self.user_model).where(self.user_model.id == user_id)
        result = await session.execute(stmt)
        return result.scalars().first()

    async def get_password_credential(
        self, session: AsyncSession, user_id: uuid.UUID
    ) -> PasswordCredential | None:
        """Retrieve password credential record for a user ID."""
        stmt = select(self.credential_model).where(
            self.credential_model.user_id == user_id
        )
        result = await session.execute(stmt)
        return result.scalars().first()

    async def create_user_with_password(
        self,
        session: AsyncSession,
        email: str,
        hashed_password: str,
        is_verified: bool = False,
        is_superuser: bool = False,
    ) -> tuple[User, EmailAddress]:
        """Create new User, EmailAddress, and PasswordCredential in session without committing."""
        clean_email = email.strip().lower()

        existing = await self.get_user_by_email(session, clean_email)
        if existing:
            raise ValueError("An account with this email address already exists.")

        user = self.user_model(is_active=True, is_superuser=is_superuser)
        session.add(user)
        await session.flush()

        email_record = self.email_model(
            user_id=user.id,
            email=clean_email,
            is_verified=is_verified,
            is_primary=True,
        )
        session.add(email_record)

        credential = self.credential_model(
            user_id=user.id,
            hashed_password=hashed_password,
            password_updated_at=utc_now(),
            credential_version=1,
        )
        session.add(credential)
        await session.flush()
        await session.refresh(user)

        return user, email_record

    async def verify_email(
        self, session: AsyncSession, email: str
    ) -> EmailAddress | None:
        """Mark an email address as verified."""
        clean_email = email.strip().lower()
        stmt = select(self.email_model).where(self.email_model.email == clean_email)
        result = await session.execute(stmt)
        email_record = result.scalars().first()
        if not email_record:
            return None

        email_record.is_verified = True
        await session.flush()
        return email_record

    async def create_session(
        self,
        session: AsyncSession,
        user_id: uuid.UUID,
        raw_token: str,
        max_age_seconds: int = 86400 * 14,
        expected_credential_version: int | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> Session:
        """Create a new active session record storing hashed token bound to credential generation."""
        token_id = hash_token(raw_token)
        now = utc_now()
        expires_at = now + timedelta(seconds=max_age_seconds)

        bind = session.bind or getattr(self, "engine", None)
        is_sqlite = (
            bind is not None
            and getattr(bind, "dialect", None) is not None
            and bind.dialect.name == "sqlite"
        )

        if expected_credential_version is not None:
            if (
                type(expected_credential_version) is not int
                or expected_credential_version < 1
            ):
                raise ValueError("Invalid expected_credential_version")

            if not is_sqlite:
                lock_stmt = (
                    select(self.credential_model)
                    .where(
                        self.credential_model.user_id == user_id,
                        self.credential_model.credential_version
                        == expected_credential_version,
                    )
                    .with_for_update()
                )
                cred = (await session.execute(lock_stmt)).scalars().first()
                if not cred:
                    raise ValueError(
                        "Credential version mismatch during session creation"
                    )

            select_stmt = (
                select(
                    sa.literal(token_id).label("id"),
                    sa.literal(user_id).label("user_id"),
                    self.credential_model.credential_version.label(
                        "credential_version"
                    ),
                    sa.literal(now).label("created_at"),
                    sa.literal(expires_at).label("expires_at"),
                    sa.literal(ip_address).label("ip_address"),
                    sa.literal(user_agent).label("user_agent"),
                )
                .select_from(self.credential_model)
                .where(
                    self.credential_model.user_id == user_id,
                    self.credential_model.credential_version
                    == expected_credential_version,
                )
            )

            insert_stmt = sa.insert(self.session_model).from_select(
                [
                    "id",
                    "user_id",
                    "credential_version",
                    "created_at",
                    "expires_at",
                    "ip_address",
                    "user_agent",
                ],
                select_stmt,
            )
            result = await session.execute(insert_stmt)
            count = (
                result.rowcount
                if isinstance(result, CursorResult)
                else (getattr(result, "rowcount", 0) or 0)
            )
            if count != 1:
                raise ValueError("Credential version mismatch during session creation")

            query_stmt = select(self.session_model).where(
                self.session_model.id == token_id
            )
            session_res: Any = (await session.execute(query_stmt)).scalars().first()
            if not session_res:
                raise ValueError("Failed reading inserted session record")
            return session_res
        else:
            select_stmt = (
                select(
                    sa.literal(token_id).label("id"),
                    sa.literal(user_id).label("user_id"),
                    sa.func.coalesce(self.credential_model.credential_version, 1).label(
                        "credential_version"
                    ),
                    sa.literal(now).label("created_at"),
                    sa.literal(expires_at).label("expires_at"),
                    sa.literal(ip_address).label("ip_address"),
                    sa.literal(user_agent).label("user_agent"),
                )
                .select_from(self.user_model)
                .outerjoin(
                    self.credential_model,
                    self.credential_model.user_id == self.user_model.id,
                )
                .where(self.user_model.id == user_id)
            )

            insert_stmt = sa.insert(self.session_model).from_select(
                [
                    "id",
                    "user_id",
                    "credential_version",
                    "created_at",
                    "expires_at",
                    "ip_address",
                    "user_agent",
                ],
                select_stmt,
            )
            result = await session.execute(insert_stmt)
            count = (
                result.rowcount
                if isinstance(result, CursorResult)
                else (getattr(result, "rowcount", 0) or 0)
            )
            if count != 1:
                raise ValueError("Failed creating session for user")

            query_stmt = select(self.session_model).where(
                self.session_model.id == token_id
            )
            session_res = (await session.execute(query_stmt)).scalars().first()
            if not session_res:
                raise ValueError("Failed reading inserted session record")
            return session_res

    async def get_session_and_user(
        self, session: AsyncSession, raw_token: str
    ) -> tuple[Session, User] | None:
        """Retrieve active unexpired session and user by raw token matching credential generation."""
        token_id = hash_token(raw_token)
        stmt = (
            select(self.session_model, self.user_model)
            .join(self.user_model, self.user_model.id == self.session_model.user_id)
            .outerjoin(
                self.credential_model,
                self.credential_model.user_id == self.user_model.id,
            )
            .where(
                self.session_model.id == token_id,
                self.session_model.expires_at > utc_now(),
                self.user_model.is_active.is_(True),
                sa.or_(
                    self.credential_model.id.is_(None),
                    self.session_model.credential_version
                    == self.credential_model.credential_version,
                ),
            )
        )
        result = await session.execute(stmt)
        row = result.first()
        if not row:
            return None
        return row[0], row[1]

    async def update_session_credential_version(
        self, session: AsyncSession, raw_token: str, new_credential_version: int
    ) -> bool:
        """Update active session record to new credential generation."""
        token_id = hash_token(raw_token)
        stmt = (
            update(self.session_model)
            .where(self.session_model.id == token_id)
            .values(credential_version=new_credential_version)
        )
        result = await session.execute(stmt)
        count = (
            result.rowcount
            if isinstance(result, CursorResult)
            else (getattr(result, "rowcount", 0) or 0)
        )
        return count == 1

    async def update_all_user_sessions_credential_version(
        self, session: AsyncSession, user_id: uuid.UUID, new_credential_version: int
    ) -> int:
        """Update all active session records for a user to new credential generation."""
        stmt = (
            update(self.session_model)
            .where(self.session_model.user_id == user_id)
            .values(credential_version=new_credential_version)
        )
        result = await session.execute(stmt)
        return (
            result.rowcount
            if isinstance(result, CursorResult)
            else (getattr(result, "rowcount", 0) or 0)
        )

    async def revoke_session(self, session: AsyncSession, raw_token: str) -> bool:
        """Delete an active session by token."""
        token_id = hash_token(raw_token)
        stmt = delete(self.session_model).where(self.session_model.id == token_id)
        result = await session.execute(stmt)
        count = (
            result.rowcount
            if isinstance(result, CursorResult)
            else (getattr(result, "rowcount", 0) or 0)
        )
        return count > 0

    async def revoke_all_user_sessions(
        self, session: AsyncSession, user_id: uuid.UUID
    ) -> int:
        """Delete all active sessions for a user."""
        stmt = delete(self.session_model).where(self.session_model.user_id == user_id)
        result = await session.execute(stmt)
        count = (
            result.rowcount
            if isinstance(result, CursorResult)
            else (getattr(result, "rowcount", 0) or 0)
        )
        return int(count)

    async def revoke_other_user_sessions(
        self, session: AsyncSession, user_id: uuid.UUID, current_raw_token: str
    ) -> int:
        """Revoke all active sessions for a user except the current session."""
        current_token_id = hash_token(current_raw_token)
        stmt = delete(self.session_model).where(
            self.session_model.user_id == user_id,
            self.session_model.id != current_token_id,
        )
        result = await session.execute(stmt)
        count = (
            result.rowcount
            if isinstance(result, CursorResult)
            else (getattr(result, "rowcount", 0) or 0)
        )
        return int(count)

    async def update_password_if_version(
        self,
        session: AsyncSession,
        user_id: uuid.UUID,
        expected_version: int,
        new_hashed_password: str,
    ) -> bool:
        """Update password with Compare-And-Swap on credential_version and increment version."""
        if type(expected_version) is not int or expected_version < 1:
            return False

        now = utc_now()
        stmt = (
            update(self.credential_model)
            .where(
                self.credential_model.user_id == user_id,
                self.credential_model.credential_version == expected_version,
            )
            .values(
                hashed_password=new_hashed_password,
                password_updated_at=now,
                updated_at=now,
                credential_version=expected_version + 1,
            )
            .execution_options(synchronize_session=False)
        )
        res = await session.execute(stmt)
        rowcount = (
            res.rowcount
            if isinstance(res, CursorResult)
            else (getattr(res, "rowcount", 0) or 0)
        )
        if rowcount != 1:
            return False

        await session.flush()
        return True

    async def atomic_reset_password(
        self,
        session: AsyncSession,
        user_id: uuid.UUID,
        expected_cred_v: int,
        new_hashed_password: str,
    ) -> bool:
        """Atomically verify credential_version CAS, update password, increment version and revoke sessions."""
        if type(expected_cred_v) is not int or expected_cred_v < 1:
            return False

        now = utc_now()
        update_stmt = (
            update(self.credential_model)
            .where(
                self.credential_model.user_id == user_id,
                self.credential_model.credential_version == expected_cred_v,
            )
            .values(
                hashed_password=new_hashed_password,
                password_updated_at=now,
                updated_at=now,
                credential_version=expected_cred_v + 1,
            )
            .execution_options(synchronize_session=False)
        )
        update_res = await session.execute(update_stmt)
        rowcount = (
            update_res.rowcount
            if isinstance(update_res, CursorResult)
            else (getattr(update_res, "rowcount", 0) or 0)
        )
        if rowcount != 1:
            return False

        await session.flush()
        # Security invariant: Revoke all active sessions upon password reset
        await self.revoke_all_user_sessions(session, user_id)
        return True
