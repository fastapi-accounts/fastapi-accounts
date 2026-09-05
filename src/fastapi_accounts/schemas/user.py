import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class EmailAddressRead(BaseModel):
    """Schema for returning user email address metadata."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    is_verified: bool
    is_primary: bool
    created_at: datetime


class UserRead(BaseModel):
    """Schema for returning user profile and account details."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    primary_email: Optional[str] = None
    is_active: bool
    is_superuser: bool
    created_at: datetime
    emails: list[EmailAddressRead] = []


class SessionRead(BaseModel):
    """Schema for returning active session details."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    created_at: datetime
    expires_at: datetime
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
