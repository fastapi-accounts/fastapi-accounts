import uuid
from collections.abc import AsyncGenerator
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Type

from sqlalchemy import delete, select
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
from fastapi_accounts.security.password import hash_password, verify_password
from fastapi_accounts.security.tokens import hash_token


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SQLAlchemyAdapter:
    """Async SQLAlchemy database adapter for FastAPI Accounts."""

    def __init__(
        self,
        database_url: Optional[str] = None,
        engine: Optional[AsyncEngine] = None,
        session_maker: Optional[async_sessionmaker[AsyncSession]] = None,
        user_model: Type[User] = User,
        email_model: Type[EmailAddress] = EmailAddress,
        credential_model: Type[PasswordCredential] = PasswordCredential,
        session_model: Type[Session] = Session,
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
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    async def get_user_by_email(
        self, session: AsyncSession, email: str
    ) -> Optional[User]:
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
    ) -> Optional[User]:
        """Retrieve user by primary UUID."""
        stmt = select(self.user_model).where(self.user_model.id == user_id)
        result = await session.execute(stmt)
        return result.scalars().first()

    async def create_user_with_password(
        self,
        session: AsyncSession,
        email: str,
        password: str,
        is_verified: bool = False,
        is_superuser: bool = False,
    ) -> tuple[User, EmailAddress]:
        """Create new User, primary EmailAddress, and PasswordCredential within the session."""
        clean_email = email.strip().lower()

        # Check if email already exists
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
            hashed_password=hash_password(password),
        )
        session.add(credential)
        await session.flush()
        await session.refresh(user)

        return user, email_record

    async def authenticate_user(
        self, session: AsyncSession, email: str, password: str
    ) -> Optional[User]:
        """Verify password credentials for a user by email."""
        user = await self.get_user_by_email(session, email)
        if not user or not user.is_active:
            return None

        # Fetch credential
        stmt = select(self.credential_model).where(
            self.credential_model.user_id == user.id
        )
        result = await session.execute(stmt)
        cred = result.scalars().first()
        if not cred:
            return None

        if not verify_password(password, cred.hashed_password):
            return None

        return user

    async def verify_email(
        self, session: AsyncSession, email: str
    ) -> Optional[EmailAddress]:
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
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Session:
        """Create a new active session record storing the hashed token."""
        token_id = hash_token(raw_token)
        expires_at = utc_now() + timedelta(seconds=max_age_seconds)

        session_record = self.session_model(
            id=token_id,
            user_id=user_id,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        session.add(session_record)
        await session.flush()
        return session_record

    async def get_session_and_user(
        self, session: AsyncSession, raw_token: str
    ) -> Optional[tuple[Session, User]]:
        """Retrieve active unexpired session and its associated user by raw token."""
        token_id = hash_token(raw_token)
        stmt = (
            select(self.session_model, self.user_model)
            .join(self.user_model, self.user_model.id == self.session_model.user_id)
            .where(
                self.session_model.id == token_id,
                self.session_model.expires_at > utc_now(),
                self.user_model.is_active.is_(True),
            )
        )
        result = await session.execute(stmt)
        row = result.first()
        if not row:
            return None
        return row[0], row[1]

    async def revoke_session(self, session: AsyncSession, raw_token: str) -> bool:
        """Delete an active session by token."""
        token_id = hash_token(raw_token)
        stmt = delete(self.session_model).where(self.session_model.id == token_id)
        result = await session.execute(stmt)
        return (result.rowcount or 0) > 0

    async def revoke_all_user_sessions(
        self, session: AsyncSession, user_id: uuid.UUID
    ) -> int:
        """Delete all active sessions for a user."""
        stmt = delete(self.session_model).where(self.session_model.user_id == user_id)
        result = await session.execute(stmt)
        return result.rowcount or 0
