"""SMTP service for sending emails."""

import logging
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

import aiosmtplib

from app.models.config import SMTPEncryption, SMTPSettings

logger = logging.getLogger(__name__)


class SMTPService:
    """Service for sending emails via SMTP."""

    def __init__(self, settings: SMTPSettings):
        """Initialize SMTP service.

        Args:
            settings: SMTP configuration settings
        """
        self.settings = settings

    async def test_connection(self) -> tuple[bool, Optional[str]]:
        """Test SMTP connection.

        Returns:
            Tuple of (success, error_message)
        """
        if not self.settings.enabled:
            return False, "SMTP is disabled"

        try:
            # Create appropriate SSL context
            if self.settings.encryption == SMTPEncryption.SSL:
                use_tls = True
                start_tls = False
            elif self.settings.encryption == SMTPEncryption.STARTTLS:
                use_tls = False
                start_tls = True
            else:  # none
                use_tls = False
                start_tls = False

            # Connect to SMTP server
            async with aiosmtplib.SMTP(
                hostname=self.settings.host,
                port=self.settings.port,
                use_tls=use_tls,
                start_tls=start_tls,
                timeout=self.settings.timeout_seconds,
            ) as smtp:
                # Authenticate if credentials provided
                if self.settings.username and self.settings.password:
                    await smtp.login(self.settings.username, self.settings.password)

                logger.info(f"SMTP connection successful to {self.settings.host}:{self.settings.port}")
                return True, None

        except aiosmtplib.SMTPAuthenticationError as e:
            error_msg = f"SMTP authentication failed: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
        except aiosmtplib.SMTPConnectError as e:
            error_msg = f"Failed to connect to SMTP server: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"SMTP connection error: {str(e)}"
            logger.error(error_msg)
            return False, error_msg

    async def send_email(
        self,
        recipient: str,
        subject: str,
        html_body: str,
        text_body: str,
    ) -> tuple[bool, Optional[str], Optional[str]]:
        """Send an email.

        Args:
            recipient: Recipient email address
            subject: Email subject
            html_body: HTML email body
            text_body: Plain text email body

        Returns:
            Tuple of (success, message_id, error_message)
        """
        if not self.settings.enabled:
            return False, None, "SMTP is disabled"

        try:
            # Create message
            message = MIMEMultipart("alternative")
            message["From"] = f"{self.settings.sender_name} <{self.settings.sender_email}>"
            message["To"] = recipient
            message["Subject"] = subject

            # Attach text and HTML parts
            part1 = MIMEText(text_body, "plain")
            part2 = MIMEText(html_body, "html")
            message.attach(part1)
            message.attach(part2)

            # Create appropriate SSL context
            if self.settings.encryption == SMTPEncryption.SSL:
                use_tls = True
                start_tls = False
            elif self.settings.encryption == SMTPEncryption.STARTTLS:
                use_tls = False
                start_tls = True
            else:  # none
                use_tls = False
                start_tls = False

            # Send email
            async with aiosmtplib.SMTP(
                hostname=self.settings.host,
                port=self.settings.port,
                use_tls=use_tls,
                start_tls=start_tls,
                timeout=self.settings.timeout_seconds,
            ) as smtp:
                # Authenticate if credentials provided
                if self.settings.username and self.settings.password:
                    await smtp.login(self.settings.username, self.settings.password)

                # Send message
                await smtp.send_message(message)

            message_id = message.get("Message-ID")
            logger.info(f"Email sent successfully to {recipient} (subject: {subject})")
            return True, message_id, None

        except aiosmtplib.SMTPAuthenticationError as e:
            error_msg = f"SMTP authentication failed: {str(e)}"
            logger.error(error_msg)
            return False, None, error_msg
        except aiosmtplib.SMTPRecipientsRefused as e:
            error_msg = f"Recipient refused: {str(e)}"
            logger.error(error_msg)
            return False, None, error_msg
        except Exception as e:
            error_msg = f"Failed to send email: {str(e)}"
            logger.error(error_msg)
            return False, None, error_msg

    async def send_bulk_email(
        self,
        recipients: list[str],
        subject: str,
        html_body: str,
        text_body: str,
    ) -> list[tuple[str, bool, Optional[str], Optional[str]]]:
        """Send email to multiple recipients.

        Args:
            recipients: List of recipient email addresses
            subject: Email subject
            html_body: HTML email body
            text_body: Plain text email body

        Returns:
            List of tuples (recipient, success, message_id, error_message)
        """
        results = []
        for recipient in recipients:
            success, message_id, error = await self.send_email(
                recipient=recipient,
                subject=subject,
                html_body=html_body,
                text_body=text_body,
            )
            results.append((recipient, success, message_id, error))
        return results
