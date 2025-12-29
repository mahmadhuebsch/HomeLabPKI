"""Authentication data models."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    """Login request model."""

    password: str = Field(..., min_length=1)


class LoginResponse(BaseModel):
    """Login response model."""

    token: str
    expires_at: datetime


class ChangePasswordRequest(BaseModel):
    """Change password request model."""

    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8)


class SessionInfo(BaseModel):
    """Session information."""

    created_at: datetime
    expires_at: datetime
    is_valid: bool


class Session(BaseModel):
    """Internal session model."""

    token: str
    created_at: datetime
    expires_at: datetime
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None
