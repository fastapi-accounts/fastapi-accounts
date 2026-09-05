from pydantic import BaseModel, ConfigDict, EmailStr, Field


class RegisterRequest(BaseModel):
    """Schema for user registration."""

    email: EmailStr
    password: str = Field(..., min_length=8, description="Password must be at least 8 characters.")


class LoginRequest(BaseModel):
    """Schema for user password login."""

    email: EmailStr
    password: str


class EmailVerificationRequest(BaseModel):
    """Schema for email verification confirmation."""

    token: str


class RequestVerificationEmailRequest(BaseModel):
    """Schema for requesting a new email verification token."""

    email: EmailStr


class TokenResponse(BaseModel):
    """Schema returned for Bearer token authorization."""

    model_config = ConfigDict(from_attributes=True)

    access_token: str
    token_type: str = "bearer"
