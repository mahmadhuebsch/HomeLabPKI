"""Application configuration models."""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, EmailStr, field_validator


class AppSettings(BaseModel):
    """Application settings."""

    title: str = "HomeLab PKI"
    version: str = "1.1.0-dev"
    debug: bool = False


class PathSettings(BaseModel):
    """Path settings."""

    ca_data: str = "./ca-data"
    logs: str = "./logs"
    openssl: Optional[str] = None


class CADefaults(BaseModel):
    """Default settings for CAs."""

    validity_days: int
    key_algorithm: str
    key_size: int


class SecuritySettings(BaseModel):
    """Security settings."""

    warn_on_key_download: bool = True
    key_download_confirmation: bool = True


class LoggingSettings(BaseModel):
    """Logging settings."""

    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file: str = "./logs/homelabpki.log"


class AuthSettings(BaseModel):
    """Authentication settings."""

    enabled: bool = True
    password_hash: Optional[str] = None  # bcrypt hash, auto-set on first run
    session_expiry_hours: int = 24


class CRLSettings(BaseModel):
    """CRL (Certificate Revocation List) settings."""

    # Base URL for CRL distribution (e.g., "http://pki.example.com:8000")
    # If set, certificates will include a CRL Distribution Point extension
    # pointing to: {base_url}/download/crl/{ca_id}.crl
    base_url: Optional[str] = None
    # CRL validity period in days (default 30)
    validity_days: int = 30


class SMTPEncryption(str, Enum):
    """SMTP encryption modes."""

    NONE = "none"
    STARTTLS = "starttls"
    SSL = "ssl"


class SMTPSettings(BaseModel):
    """SMTP configuration settings."""

    enabled: bool = False
    host: str = "smtp.example.com"
    port: int = 587
    encryption: SMTPEncryption = SMTPEncryption.STARTTLS
    username: Optional[str] = None
    password: Optional[str] = None
    sender_email: str = "pki@example.com"
    sender_name: str = "HomeLab PKI"
    timeout_seconds: int = 30

    @field_validator("port")
    @classmethod
    def validate_port(cls, v: int) -> int:
        """Validate port is in valid range."""
        if not 1 <= v <= 65535:
            raise ValueError("Port must be between 1 and 65535")
        return v


class NotificationSecuritySettings(BaseModel):
    """Security settings for notifications."""

    include_internal_urls: bool = True
    include_serial_number: bool = True
    include_subject_dn: bool = True
    mask_email_addresses: bool = False


class NotificationRateLimitSettings(BaseModel):
    """Rate limiting settings for notifications."""

    max_emails_per_hour: int = 50
    max_emails_per_day: int = 200
    cooldown_minutes: int = 5


class NotificationErrorHandlingSettings(BaseModel):
    """Error handling settings for notifications."""

    max_retries: int = 3
    retry_delays: list[int] = [5, 15, 60]
    fail_silently: bool = False


class NotificationSettings(BaseModel):
    """Notification configuration settings."""

    enabled: bool = False
    recipients: list[str] = []
    thresholds: list[int] = [90, 60, 30, 14, 7, 3, 1]
    check_interval_hours: int = 24
    check_on_startup: bool = True
    include_ca_expiry: bool = True
    include_cert_expiry: bool = True
    include_crl_expiry: bool = True
    digest_mode: bool = False
    security: NotificationSecuritySettings = NotificationSecuritySettings()
    rate_limit: NotificationRateLimitSettings = NotificationRateLimitSettings()
    error_handling: NotificationErrorHandlingSettings = NotificationErrorHandlingSettings()

    @field_validator("thresholds")
    @classmethod
    def validate_thresholds(cls, v: list[int]) -> list[int]:
        """Validate thresholds are in descending order."""
        if v != sorted(v, reverse=True):
            raise ValueError("Thresholds must be in descending order")
        return v


class EmailTemplateSettings(BaseModel):
    """Email template settings."""

    subject_warning: str = "[HomeLab PKI] {{ entity_type }} '{{ entity_name }}' expires in {{ days_remaining }} days"
    subject_expired: str = "[HomeLab PKI] EXPIRED: {{ entity_type }} '{{ entity_name }}'"
    subject_digest: str = "[HomeLab PKI] Certificate Expiry Summary - {{ item_count }} items"
    subject_test: str = "[HomeLab PKI] Test Email"


class AppConfig(BaseModel):
    """Main application configuration."""

    app: AppSettings
    paths: PathSettings
    defaults: dict[str, CADefaults]
    security: SecuritySettings
    logging: LoggingSettings
    auth: AuthSettings = AuthSettings()
    crl: CRLSettings = CRLSettings()
    smtp: SMTPSettings = SMTPSettings()
    notifications: NotificationSettings = NotificationSettings()
    email_templates: EmailTemplateSettings = EmailTemplateSettings()
