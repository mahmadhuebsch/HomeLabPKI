"""Notification API endpoints."""

import logging
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from app.api.dependencies import get_config, get_notification_service, get_smtp_service, require_auth
from app.models.auth import Session
from app.models.config import AppConfig
from app.models.notification import (
    NotificationCheckResult,
    NotificationStatusResponse,
    NotificationTestRequest,
    NotificationTestResponse,
)
from app.services.notification_service import NotificationService
from app.services.smtp_service import SMTPService

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/notifications",
    tags=["notifications"],
)


@router.get("/status", response_model=NotificationStatusResponse)
async def get_notification_status(
    session: Annotated[Session, Depends(require_auth)],
    notification_service: Annotated[NotificationService, Depends(get_notification_service)],
    smtp_service: Annotated[SMTPService, Depends(get_smtp_service)],
    config: Annotated[AppConfig, Depends(get_config)],
) -> NotificationStatusResponse:
    """Get notification system status."""
    # Test SMTP connection
    smtp_connected = False
    if config.smtp.enabled:
        smtp_connected, _ = await smtp_service.test_connection()

    # Load state to get last check time
    state_file = notification_service.notifications_dir / "state.yaml"
    last_check = None
    if state_file.exists():
        try:
            from app.services.yaml_service import YAMLService
            from datetime import datetime

            data = YAMLService.load_config_yaml(state_file)
            if "last_check_run" in data:
                last_check = datetime.fromisoformat(data["last_check_run"])
        except Exception:
            pass

    # Calculate next check (if enabled and interval configured)
    next_check = None
    if last_check and config.notifications.enabled:
        from datetime import timedelta

        next_check = last_check + timedelta(hours=config.notifications.check_interval_hours)

    return NotificationStatusResponse(
        enabled=config.notifications.enabled,
        smtp_configured=config.smtp.enabled,
        smtp_connected=smtp_connected,
        last_check=last_check,
        next_check=next_check,
        pending_notifications=0,  # TODO: Calculate from state
        recent_errors=[],
    )


@router.post("/check", response_model=NotificationCheckResult)
async def trigger_notification_check(
    session: Annotated[Session, Depends(require_auth)],
    notification_service: Annotated[NotificationService, Depends(get_notification_service)],
    config: Annotated[AppConfig, Depends(get_config)],
) -> NotificationCheckResult:
    """Trigger manual expiration check and send notifications."""
    if not config.notifications.enabled:
        raise HTTPException(status_code=400, detail="Notifications are disabled")

    if not config.smtp.enabled:
        raise HTTPException(status_code=400, detail="SMTP is not configured")

    logger.info("Manual notification check triggered")
    result = await notification_service.check_expirations()
    logger.info(
        f"Notification check complete: {result.notifications_sent} sent, "
        f"{result.notifications_skipped} skipped, {len(result.errors)} errors"
    )
    return result


@router.post("/test", response_model=NotificationTestResponse)
async def send_test_notification(
    request: NotificationTestRequest,
    session: Annotated[Session, Depends(require_auth)],
    notification_service: Annotated[NotificationService, Depends(get_notification_service)],
    config: Annotated[AppConfig, Depends(get_config)],
) -> NotificationTestResponse:
    """Send a test email to verify SMTP configuration."""
    if not config.smtp.enabled:
        raise HTTPException(status_code=400, detail="SMTP is not configured")

    from datetime import datetime

    logger.info(f"Sending test email to {request.recipient}")
    success, message_id, error = await notification_service.send_test_email(request.recipient)

    return NotificationTestResponse(
        success=success,
        message_id=message_id,
        sent_at=datetime.now(),
        error=error,
    )


@router.post("/smtp/test")
async def test_smtp_connection(
    session: Annotated[Session, Depends(require_auth)],
    smtp_service: Annotated[SMTPService, Depends(get_smtp_service)],
    config: Annotated[AppConfig, Depends(get_config)],
) -> dict:
    """Test SMTP connection without sending email."""
    if not config.smtp.enabled:
        raise HTTPException(status_code=400, detail="SMTP is not configured")

    logger.info("Testing SMTP connection")
    success, error = await smtp_service.test_connection()

    return {
        "success": success,
        "error": error,
    }


@router.post("/reset")
async def reset_notification_state(
    session: Annotated[Session, Depends(require_auth)],
    notification_service: Annotated[NotificationService, Depends(get_notification_service)],
) -> dict:
    """Reset all notification state."""
    logger.info("Resetting all notification state")
    notification_service.reset_state()
    return {"message": "Notification state reset"}


@router.post("/reset/{entity_id:path}")
async def reset_entity_notification_state(
    entity_id: str,
    session: Annotated[Session, Depends(require_auth)],
    notification_service: Annotated[NotificationService, Depends(get_notification_service)],
) -> dict:
    """Reset notification state for a specific entity."""
    logger.info(f"Resetting notification state for {entity_id}")
    notification_service.reset_state(entity_id)
    return {"message": f"Notification state reset for {entity_id}"}


@router.get("/config")
async def get_notification_config(
    session: Annotated[Session, Depends(require_auth)],
    config: Annotated[AppConfig, Depends(get_config)],
) -> dict:
    """Get current notification configuration."""
    return {
        "smtp": config.smtp.model_dump(exclude={"password"}),  # Don't expose password
        "notifications": config.notifications.model_dump(),
        "email_templates": config.email_templates.model_dump(),
    }
