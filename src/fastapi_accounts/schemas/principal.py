from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class UserPrincipal(BaseModel):
    """Immutable identity principal DTO returned by authentication dependencies."""

    model_config = ConfigDict(from_attributes=True, frozen=True)

    id: uuid.UUID
    email: str | None = None
    is_active: bool = True
    is_superuser: bool = False
    is_verified: bool = False
    created_at: datetime | None = None
    updated_at: datetime | None = None
