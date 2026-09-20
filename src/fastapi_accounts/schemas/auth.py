from pydantic import BaseModel, ConfigDict, EmailStr, field_validator


def _validate_password_bytes(v: str, min_len: int = 8) -> str:
    if not isinstance(v, str):
        raise TypeError("Password must be a string.")
    if len(v) < min_len:
        raise ValueError(f"Password must be at least {min_len} characters.")
    byte_len = len(v.encode("utf-8"))
    if byte_len > 128:
        raise ValueError(
            f"Password exceeds maximum length of 128 bytes (received {byte_len} bytes)."
        )
    return v


class RegisterRequest(BaseModel):
    """Schema for user registration."""

    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return _validate_password_bytes(v, min_len=8)


class LoginRequest(BaseModel):
    """Schema for user password login."""

    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return _validate_password_bytes(v, min_len=1)


class EmailVerificationRequest(BaseModel):
    """Schema for email verification confirmation."""

    token: str


class RequestVerificationEmailRequest(BaseModel):
    """Schema for requesting a new email verification token."""

    email: EmailStr


class RequestPasswordResetRequest(BaseModel):
    """Schema for requesting a password reset token."""

    email: EmailStr


class ResetPasswordRequest(BaseModel):
    """Schema for completing a password reset."""

    token: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        return _validate_password_bytes(v, min_len=8)


class TokenResponse(BaseModel):
    """Schema returned for Bearer token authorization."""

    model_config = ConfigDict(from_attributes=True)

    access_token: str
    token_type: str = "bearer"


class ChangePasswordRequest(BaseModel):
    """Schema for authenticated password change."""

    current_password: str
    new_password: str
    revoke_other_sessions: bool = True

    @field_validator("current_password")
    @classmethod
    def validate_current_password(cls, v: str) -> str:
        return _validate_password_bytes(v, min_len=1)

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        return _validate_password_bytes(v, min_len=8)
