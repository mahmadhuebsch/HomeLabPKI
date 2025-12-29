"""Application configuration models."""

from typing import Optional

from pydantic import BaseModel


class AppSettings(BaseModel):
    """Application settings."""

    title: str = "HomeLab PKI"
    version: str = "1.0.0"
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


class AppConfig(BaseModel):
    """Main application configuration."""

    app: AppSettings
    paths: PathSettings
    defaults: dict[str, CADefaults]
    security: SecuritySettings
    logging: LoggingSettings
    auth: AuthSettings = AuthSettings()
