from typing import Optional

from sqlalchemy.orm import DeclarativeBase, Mapped, relationship

from fastapi_accounts.models.mixins import (
    EmailAddressMixin,
    PasswordCredentialMixin,
    SessionMixin,
    UserMixin,
)


class Base(DeclarativeBase):
    pass


class User(Base, UserMixin):
    __tablename__ = "users"

    emails: Mapped[list["EmailAddress"]] = relationship(
        "EmailAddress", back_populates="user", cascade="all, delete-orphan", lazy="selectin"
    )
    password_credential: Mapped[Optional["PasswordCredential"]] = relationship(
        "PasswordCredential",
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    sessions: Mapped[list["Session"]] = relationship(
        "Session", back_populates="user", cascade="all, delete-orphan"
    )

    @property
    def primary_email(self) -> Optional[str]:
        for e in self.emails:
            if e.is_primary:
                return e.email
        if self.emails:
            return self.emails[0].email
        return None


class EmailAddress(Base, EmailAddressMixin):
    __tablename__ = "email_addresses"

    user: Mapped["User"] = relationship("User", back_populates="emails")


class PasswordCredential(Base, PasswordCredentialMixin):
    __tablename__ = "password_credentials"

    user: Mapped["User"] = relationship("User", back_populates="password_credential")


class Session(Base, SessionMixin):
    __tablename__ = "sessions"

    user: Mapped["User"] = relationship("User", back_populates="sessions")
