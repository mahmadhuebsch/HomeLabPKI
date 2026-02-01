"""Notification service for expiry warnings."""

import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.models.config import (
    AppConfig,
    EmailTemplateSettings,
    NotificationSettings,
    SMTPSettings,
)
from app.models.notification import (
    NotificationCheckResult,
    NotificationEntityType,
    NotificationLogEntry,
    NotificationOverride,
    NotificationState,
    NotificationStatus,
)
from app.services.parser_service import CertificateParser
from app.services.smtp_service import SMTPService
from app.services.yaml_service import YAMLService

logger = logging.getLogger(__name__)


class NotificationService:
    """Service for managing certificate expiration notifications."""

    def __init__(
        self,
        ca_data_dir: Path,
        config: AppConfig,
        smtp_service: SMTPService,
    ):
        """Initialize notification service.

        Args:
            ca_data_dir: Base directory for CA data storage
            config: Application configuration
            smtp_service: SMTP service instance
        """
        self.ca_data_dir = ca_data_dir
        self.config = config
        self.smtp_service = smtp_service
        self.notifications_dir = ca_data_dir / ".notifications"
        self.state_file = self.notifications_dir / "state.yaml"
        self.log_dir = self.notifications_dir / "log"

        # Ensure directories exist
        self.notifications_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Initialize Jinja2 for email templates
        template_dir = Path(__file__).parent.parent / "templates" / "email"
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(enabled_extensions=("html", "txt"), default_for_string=True),
        )

    def _load_state(self) -> dict[str, NotificationState]:
        """Load notification state from disk.

        Returns:
            Dictionary mapping entity IDs to notification states
        """
        if not self.state_file.exists():
            return {}

        try:
            data = YAMLService.load_config_yaml(self.state_file)
            state_dict = {}
            for entity_id, state_data in data.get("sent_notifications", {}).items():
                state_dict[entity_id] = NotificationState(**state_data)
            return state_dict
        except Exception as e:
            logger.error(f"Failed to load notification state: {e}")
            return {}

    def _save_state(self, state: dict[str, NotificationState]) -> None:
        """Save notification state to disk.

        Args:
            state: Dictionary mapping entity IDs to notification states
        """
        try:
            data = {
                "sent_notifications": {entity_id: ns.model_dump() for entity_id, ns in state.items()},
                "last_check_run": datetime.now().isoformat(),
            }
            YAMLService.save_config_yaml(self.state_file, data)
        except Exception as e:
            logger.error(f"Failed to save notification state: {e}")

    def _log_notification(self, entry: NotificationLogEntry) -> None:
        """Log a notification to monthly log file.

        Args:
            entry: Notification log entry
        """
        try:
            # Determine log file based on month
            log_file = self.log_dir / f"{entry.timestamp.strftime('%Y-%m')}.yaml"

            # Load existing logs
            if log_file.exists():
                data = YAMLService.load_config_yaml(log_file)
                notifications = data.get("notifications", [])
            else:
                notifications = []

            # Append new entry
            notifications.append(entry.model_dump())

            # Save
            YAMLService.save_config_yaml(log_file, {"notifications": notifications})
        except Exception as e:
            logger.error(f"Failed to log notification: {e}")

    def _load_entity_override(self, entity_path: Path) -> Optional[NotificationOverride]:
        """Load notification overrides for an entity.

        Args:
            entity_path: Path to entity directory

        Returns:
            Notification override settings or None
        """
        config_file = entity_path / "config.yaml"
        if not config_file.exists():
            return None

        try:
            data = YAMLService.load_config_yaml(config_file)
            if "notifications" in data:
                return NotificationOverride(**data["notifications"])
        except Exception as e:
            logger.error(f"Failed to load entity override from {config_file}: {e}")
        return None

    def _get_effective_settings(
        self,
        entity_path: Path,
    ) -> tuple[bool, list[str], list[int]]:
        """Get effective notification settings for an entity.

        Args:
            entity_path: Path to entity directory

        Returns:
            Tuple of (enabled, recipients, thresholds)
        """
        # Start with global settings
        enabled = self.config.notifications.enabled
        recipients = list(self.config.notifications.recipients)
        thresholds = list(self.config.notifications.thresholds)

        # Apply entity overrides
        override = self._load_entity_override(entity_path)
        if override:
            if override.enabled is not None:
                enabled = override.enabled
            if override.recipients:
                # Add entity recipients to global recipients
                recipients.extend(override.recipients)
                recipients = list(set(recipients))  # Deduplicate
            if override.thresholds is not None:
                # Entity thresholds replace global thresholds
                thresholds = override.thresholds

        return enabled, recipients, thresholds

    def _render_template(
        self,
        template_name: str,
        variables: dict[str, str],
    ) -> str:
        """Render email template.

        Args:
            template_name: Template filename
            variables: Template variables

        Returns:
            Rendered template content
        """
        try:
            template = self.jinja_env.get_template(template_name)
            return template.render(**variables)
        except Exception as e:
            logger.error(f"Failed to render template {template_name}: {e}")
            return ""

    def _get_days_until_expiry(self, expiry_date: datetime) -> int:
        """Calculate days until expiry.

        Args:
            expiry_date: Expiration date

        Returns:
            Number of days until expiry (can be negative if expired)
        """
        delta = expiry_date - datetime.now()
        return delta.days

    def _get_base_url(self) -> Optional[str]:
        """Get base URL for PKI dashboard links.

        Returns:
            Base URL or None if not configured
        """
        # This could be configured in settings
        # For now, we'll use CRL base_url as a proxy
        return self.config.crl.base_url

    async def _send_expiry_notification(
        self,
        entity_id: str,
        entity_type: NotificationEntityType,
        entity_name: str,
        expiry_date: datetime,
        days_remaining: int,
        recipients: list[str],
        additional_vars: Optional[dict[str, str]] = None,
    ) -> tuple[bool, Optional[str]]:
        """Send expiry notification email.

        Args:
            entity_id: Entity identifier
            entity_type: Type of entity
            entity_name: Entity name
            expiry_date: Expiration date
            days_remaining: Days until expiry
            recipients: List of recipient emails
            additional_vars: Additional template variables

        Returns:
            Tuple of (success, error_message)
        """
        # Build template variables
        variables = {
            "entity_type": entity_type.value.replace("_", " ").title(),
            "entity_name": entity_name,
            "expiry_date": expiry_date.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "days_remaining": str(days_remaining),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
        }

        # Add base URL if configured
        base_url = self._get_base_url()
        if base_url and self.config.notifications.security.include_internal_urls:
            if entity_type == NotificationEntityType.ROOT_CA:
                variables["entity_url"] = f"{base_url}/rootcas/{entity_id}"
            elif entity_type == NotificationEntityType.INTERMEDIATE_CA:
                variables["entity_url"] = f"{base_url}/intermediates/{entity_id}"
            elif entity_type == NotificationEntityType.CERTIFICATE:
                variables["entity_url"] = f"{base_url}/certs/{entity_id}"

        # Merge additional variables
        if additional_vars:
            variables.update(additional_vars)

        # Render subject from template
        subject_template = self.config.email_templates.subject_warning
        try:
            from jinja2 import Template

            subject = Template(subject_template).render(**variables)
        except Exception as e:
            logger.error(f"Failed to render subject: {e}")
            subject = f"[HomeLab PKI] {entity_name} expires in {days_remaining} days"

        # Render email body
        html_body = self._render_template("expiry_warning.html", variables)
        text_body = self._render_template("expiry_warning.txt", variables)

        # Send to all recipients
        all_success = True
        errors = []

        for recipient in recipients:
            success, message_id, error = await self.smtp_service.send_email(
                recipient=recipient,
                subject=subject,
                html_body=html_body,
                text_body=text_body,
            )
            if not success:
                all_success = False
                errors.append(f"{recipient}: {error}")

        if errors:
            return False, "; ".join(errors)
        return True, None

    async def check_expirations(self) -> NotificationCheckResult:
        """Check for expiring certificates and send notifications.

        Returns:
            Result of expiration check
        """
        checked_at = datetime.now()
        items_checked = 0
        expiring_items = 0
        notifications_sent = 0
        notifications_skipped = 0
        errors = []

        # Load current state
        state = self._load_state()

        # Check Root CAs
        if self.config.notifications.include_ca_expiry:
            for ca_dir in self.ca_data_dir.glob("root-ca-*"):
                if ca_dir.name.startswith("_"):
                    continue
                items_checked += 1
                result = await self._check_entity(
                    ca_dir,
                    "root-ca",
                    NotificationEntityType.ROOT_CA,
                    state,
                )
                if result["expiring"]:
                    expiring_items += 1
                notifications_sent += result["sent"]
                notifications_skipped += result["skipped"]
                if result["error"]:
                    errors.append(result["error"])

                # Check intermediates
                for int_dir in ca_dir.glob("intermediate-ca-*"):
                    if int_dir.name.startswith("_"):
                        continue
                    items_checked += 1
                    result = await self._check_entity(
                        int_dir,
                        f"{ca_dir.name}/{int_dir.name}",
                        NotificationEntityType.INTERMEDIATE_CA,
                        state,
                    )
                    if result["expiring"]:
                        expiring_items += 1
                    notifications_sent += result["sent"]
                    notifications_skipped += result["skipped"]
                    if result["error"]:
                        errors.append(result["error"])

        # Check Certificates
        if self.config.notifications.include_cert_expiry:
            for ca_dir in self.ca_data_dir.glob("root-ca-*"):
                if ca_dir.name.startswith("_"):
                    continue
                cert_dirs = list((ca_dir / "certs").glob("*")) if (ca_dir / "certs").exists() else []
                for cert_dir in cert_dirs:
                    if cert_dir.name.startswith("_") or not cert_dir.is_dir():
                        continue
                    items_checked += 1
                    result = await self._check_entity(
                        cert_dir,
                        f"{ca_dir.name}/certs/{cert_dir.name}",
                        NotificationEntityType.CERTIFICATE,
                        state,
                    )
                    if result["expiring"]:
                        expiring_items += 1
                    notifications_sent += result["sent"]
                    notifications_skipped += result["skipped"]
                    if result["error"]:
                        errors.append(result["error"])

                # Check intermediate CA certs
                for int_dir in ca_dir.glob("intermediate-ca-*"):
                    if int_dir.name.startswith("_"):
                        continue
                    cert_dirs = list((int_dir / "certs").glob("*")) if (int_dir / "certs").exists() else []
                    for cert_dir in cert_dirs:
                        if cert_dir.name.startswith("_") or not cert_dir.is_dir():
                            continue
                        items_checked += 1
                        result = await self._check_entity(
                            cert_dir,
                            f"{ca_dir.name}/{int_dir.name}/certs/{cert_dir.name}",
                            NotificationEntityType.CERTIFICATE,
                            state,
                        )
                        if result["expiring"]:
                            expiring_items += 1
                        notifications_sent += result["sent"]
                        notifications_skipped += result["skipped"]
                        if result["error"]:
                            errors.append(result["error"])

        # Save updated state
        self._save_state(state)

        return NotificationCheckResult(
            checked_at=checked_at,
            items_checked=items_checked,
            expiring_items=expiring_items,
            notifications_sent=notifications_sent,
            notifications_skipped=notifications_skipped,
            errors=errors,
        )

    async def _check_entity(
        self,
        entity_path: Path,
        entity_id: str,
        entity_type: NotificationEntityType,
        state: dict[str, NotificationState],
    ) -> dict:
        """Check a single entity for expiration.

        Args:
            entity_path: Path to entity directory
            entity_id: Entity identifier
            entity_type: Type of entity
            state: Current notification state (modified in place)

        Returns:
            Dictionary with check results
        """
        result = {
            "expiring": False,
            "sent": 0,
            "skipped": 0,
            "error": None,
        }

        # Get effective settings
        enabled, recipients, thresholds = self._get_effective_settings(entity_path)

        if not enabled or not recipients:
            return result

        # Load certificate
        cert_file = (
            entity_path / "ca.crt"
            if entity_type in [NotificationEntityType.ROOT_CA, NotificationEntityType.INTERMEDIATE_CA]
            else entity_path / "cert.crt"
        )
        if not cert_file.exists():
            return result

        try:
            cert_data = CertificateParser.parse_certificate(cert_file)
            expiry_date = datetime.fromisoformat(cert_data["validity"]["not_after"])
            days_remaining = self._get_days_until_expiry(expiry_date)

            # Get or create state for this entity
            if entity_id not in state:
                state[entity_id] = NotificationState()

            entity_state = state[entity_id]
            entity_state.last_checked = datetime.now()

            # Check if we need to send notification
            for threshold in thresholds:
                if days_remaining <= threshold and threshold not in entity_state.thresholds_sent:
                    result["expiring"] = True

                    # Send notification
                    additional_vars = {}
                    if self.config.notifications.security.include_serial_number:
                        additional_vars["serial_number"] = cert_data.get("serial_number", "")
                    if self.config.notifications.security.include_subject_dn:
                        additional_vars["subject"] = cert_data.get("subject", "")
                        additional_vars["issuer"] = cert_data.get("issuer", "")
                    additional_vars["key_algorithm"] = cert_data.get("key_algorithm", "")

                    success, error = await self._send_expiry_notification(
                        entity_id=entity_id,
                        entity_type=entity_type,
                        entity_name=cert_data.get("subject", {}).get("common_name", entity_id),
                        expiry_date=expiry_date,
                        days_remaining=days_remaining,
                        recipients=recipients,
                        additional_vars=additional_vars,
                    )

                    # Log notification
                    log_entry = NotificationLogEntry(
                        timestamp=datetime.now(),
                        entity_id=entity_id,
                        entity_type=entity_type,
                        threshold_days=threshold,
                        actual_days=days_remaining,
                        recipients=recipients,
                        status=NotificationStatus.SENT if success else NotificationStatus.FAILED,
                        error=error,
                    )
                    self._log_notification(log_entry)

                    if success:
                        entity_state.thresholds_sent.append(threshold)
                        entity_state.last_notified = datetime.now()
                        result["sent"] += 1
                    else:
                        result["error"] = error
                else:
                    if days_remaining <= threshold:
                        result["skipped"] += 1

        except Exception as e:
            logger.error(f"Error checking {entity_id}: {e}")
            result["error"] = str(e)

        return result

    async def send_test_email(self, recipient: str) -> tuple[bool, Optional[str], Optional[str]]:
        """Send a test email.

        Args:
            recipient: Recipient email address

        Returns:
            Tuple of (success, message_id, error_message)
        """
        variables = {
            "smtp_host": self.config.smtp.host,
            "smtp_port": str(self.config.smtp.port),
            "smtp_encryption": self.config.smtp.encryption.value,
            "sender_email": self.config.smtp.sender_email,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
        }

        subject = self.config.email_templates.subject_test
        html_body = self._render_template("test_email.html", variables)
        text_body = self._render_template("test_email.txt", variables)

        return await self.smtp_service.send_email(
            recipient=recipient,
            subject=subject,
            html_body=html_body,
            text_body=text_body,
        )

    def reset_state(self, entity_id: Optional[str] = None) -> None:
        """Reset notification state.

        Args:
            entity_id: Optional entity ID to reset (resets all if None)
        """
        if entity_id is None:
            # Reset all state
            self._save_state({})
        else:
            # Reset specific entity
            state = self._load_state()
            if entity_id in state:
                del state[entity_id]
                self._save_state(state)
