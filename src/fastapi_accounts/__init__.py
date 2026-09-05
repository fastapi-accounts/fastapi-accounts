"""FastAPI Accounts: Modern, zero-boilerplate authentication and account management for FastAPI."""

from fastapi_accounts.adapters.sqlalchemy import SQLAlchemyAdapter
from fastapi_accounts.core import FastAPIAccounts
from fastapi_accounts.models.default import (
    Base,
    EmailAddress,
    PasswordCredential,
    Session,
    User,
)
from fastapi_accounts.models.mixins import (
    EmailAddressMixin,
    PasswordCredentialMixin,
    SessionMixin,
    UserMixin,
)
from fastapi_accounts.schemas.auth import (
    EmailVerificationRequest,
    LoginRequest,
    RegisterRequest,
    TokenResponse,
)
from fastapi_accounts.schemas.user import EmailAddressRead, SessionRead, UserRead
from fastapi_accounts.transports.base import BaseTransport
from fastapi_accounts.transports.bearer import BearerTransport
from fastapi_accounts.transports.cookie import CookieTransport

__version__ = "0.1.0a1"

__all__ = [
    "FastAPIAccounts",
    "SQLAlchemyAdapter",
    "BaseTransport",
    "CookieTransport",
    "BearerTransport",
    "Base",
    "User",
    "EmailAddress",
    "PasswordCredential",
    "Session",
    "UserMixin",
    "EmailAddressMixin",
    "PasswordCredentialMixin",
    "SessionMixin",
    "RegisterRequest",
    "LoginRequest",
    "EmailVerificationRequest",
    "TokenResponse",
    "UserRead",
    "EmailAddressRead",
    "SessionRead",
    "__version__",
]