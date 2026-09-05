import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, declared_attr, mapped_column


def utc_now() -> datetime:
    """Return current UTC timestamp without timezone offset issues."""
    return datetime.now(timezone.utc)


class UserMixin:
    """SQLAlchemy 2.0 mixin providing the core User table columns."""

    @declared_attr
    def id(cls) -> Mapped[uuid.UUID]:
        return mapped_column(primary_key=True, default=uuid.uuid4)

    @declared_attr
    def is_active(cls) -> Mapped[bool]:
        return mapped_column(Boolean, default=True, nullable=False)

    @declared_attr
    def is_superuser(cls) -> Mapped[bool]:
        return mapped_column(Boolean, default=False, nullable=False)

    @declared_attr
    def created_at(cls) -> Mapped[datetime]:
        return mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    @declared_attr
    def updated_at(cls) -> Mapped[datetime]:
        return mapped_column(
            DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
        )


class EmailAddressMixin:
    """SQLAlchemy 2.0 mixin for managing user email addresses with verification and primary flags."""

    @declared_attr
    def id(cls) -> Mapped[uuid.UUID]:
        return mapped_column(primary_key=True, default=uuid.uuid4)

    @declared_attr
    def user_id(cls) -> Mapped[uuid.UUID]:
        return mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)

    @declared_attr
    def email(cls) -> Mapped[str]:
        return mapped_column(String(320), unique=True, index=True, nullable=False)

    @declared_attr
    def is_verified(cls) -> Mapped[bool]:
        return mapped_column(Boolean, default=False, nullable=False)

    @declared_attr
    def is_primary(cls) -> Mapped[bool]:
        return mapped_column(Boolean, default=False, nullable=False)

    @declared_attr
    def created_at(cls) -> Mapped[datetime]:
        return mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class PasswordCredentialMixin:
    """SQLAlchemy 2.0 mixin storing hashed password credentials for a user."""

    @declared_attr
    def id(cls) -> Mapped[uuid.UUID]:
        return mapped_column(primary_key=True, default=uuid.uuid4)

    @declared_attr
    def user_id(cls) -> Mapped[uuid.UUID]:
        return mapped_column(
            ForeignKey("users.id", ondelete="CASCADE"), unique=True, index=True, nullable=False
        )

    @declared_attr
    def hashed_password(cls) -> Mapped[str]:
        return mapped_column(String(1024), nullable=False)

    @declared_attr
    def created_at(cls) -> Mapped[datetime]:
        return mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    @declared_attr
    def updated_at(cls) -> Mapped[datetime]:
        return mapped_column(
            DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
        )


class SessionMixin:
    """SQLAlchemy 2.0 mixin storing active authentication sessions."""

    @declared_attr
    def id(cls) -> Mapped[str]:
        # Stores the SHA-256 hash of the session token
        return mapped_column(String(64), primary_key=True)

    @declared_attr
    def user_id(cls) -> Mapped[uuid.UUID]:
        return mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)

    @declared_attr
    def created_at(cls) -> Mapped[datetime]:
        return mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    @declared_attr
    def expires_at(cls) -> Mapped[datetime]:
        return mapped_column(DateTime(timezone=True), index=True, nullable=False)

    @declared_attr
    def ip_address(cls) -> Mapped[Optional[str]]:
        return mapped_column(String(45), nullable=True)

    @declared_attr
    def user_agent(cls) -> Mapped[Optional[str]]:
        return mapped_column(String(512), nullable=True)
