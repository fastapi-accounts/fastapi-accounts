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
    ChangePasswordRequest,
    EmailVerificationRequest,
    LoginRequest,
    RegisterRequest,
    RequestPasswordResetRequest,
    RequestVerificationEmailRequest,
    ResetPasswordRequest,
    TokenResponse,
)
from fastapi_accounts.schemas.user import EmailAddressRead, SessionRead, UserRead
from fastapi_accounts.transports.base import BaseTransport
from fastapi_accounts.transports.bearer import BearerTransport
from fastapi_accounts.transports.cookie import CookieTransport

__version__ = "0.1.0a2"

__all__ = [
    "Base",
    "BaseTransport",
    "BearerTransport",
    "ChangePasswordRequest",
    "CookieTransport",
    "EmailAddress",
    "EmailAddressMixin",
    "EmailAddressRead",
    "EmailVerificationRequest",
    "FastAPIAccounts",
    "LoginRequest",
    "PasswordCredential",
    "PasswordCredentialMixin",
    "RegisterRequest",
    "RequestPasswordResetRequest",
    "RequestVerificationEmailRequest",
    "ResetPasswordRequest",
    "SQLAlchemyAdapter",
    "Session",
    "SessionMixin",
    "SessionRead",
    "TokenResponse",
    "User",
    "UserMixin",
    "UserRead",
    "__version__",
]
