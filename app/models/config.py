"""Application configuration models."""

from pydantic import BaseModel
from typing import Optional


class AppSettings(BaseModel):
    """Application settings."""

    title: str = "CA Manager"
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
    file: str = "./logs/ca-manager.log"


class AppConfig(BaseModel):
    """Main application configuration."""

    app: AppSettings
    paths: PathSettings
    defaults: dict[str, CADefaults]
    security: SecuritySettings
    logging: LoggingSettings
