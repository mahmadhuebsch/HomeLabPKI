"""Notification models."""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel


class NotificationEntityType(str, Enum):
    """Type of entity for notification."""

    ROOT_CA = "root_ca"
    INTERMEDIATE_CA = "intermediate_ca"
    CERTIFICATE = "certificate"
    CRL = "crl"


class NotificationStatus(str, Enum):
    """Notification delivery status."""

    SENT = "sent"
    FAILED = "failed"
    SKIPPED = "skipped"


class NotificationOverride(BaseModel):
    """Per-entity notification override settings."""

    enabled: Optional[bool] = None
    recipients: list[str] = []
    thresholds: Optional[list[int]] = None


class NotificationState(BaseModel):
    """Notification state for an entity."""

    thresholds_sent: list[int] = []
    last_checked: Optional[datetime] = None
    last_notified: Optional[datetime] = None


class NotificationLogEntry(BaseModel):
    """Single notification log entry."""

    timestamp: datetime
    entity_id: str
    entity_type: NotificationEntityType
    threshold_days: int
    actual_days: int
    recipients: list[str]
    status: NotificationStatus
    message_id: Optional[str] = None
    error: Optional[str] = None


class NotificationStatusResponse(BaseModel):
    """Response model for notification status."""

    enabled: bool
    smtp_configured: bool
    smtp_connected: bool
    last_check: Optional[datetime]
    next_check: Optional[datetime]
    pending_notifications: int
    recent_errors: list[str] = []


class NotificationCheckResult(BaseModel):
    """Result of an expiration check."""

    checked_at: datetime
    items_checked: int
    expiring_items: int
    notifications_sent: int
    notifications_skipped: int
    errors: list[str] = []


class NotificationTestRequest(BaseModel):
    """Request to send a test email."""

    recipient: str


class NotificationTestResponse(BaseModel):
    """Response from test email."""

    success: bool
    message_id: Optional[str] = None
    sent_at: datetime
    error: Optional[str] = None


class NotificationPreviewResponse(BaseModel):
    """Preview of a notification email."""

    subject: str
    html_body: str
    text_body: str
    recipients: list[str]
    variables: dict[str, str]
