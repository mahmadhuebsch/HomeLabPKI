"""Application configuration models."""

from typing import Optional

from pydantic import BaseModel


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


class AppConfig(BaseModel):
    """Main application configuration."""

    app: AppSettings
    paths: PathSettings
    defaults: dict[str, CADefaults]
    security: SecuritySettings
    logging: LoggingSettings
    auth: AuthSettings = AuthSettings()
    crl: CRLSettings = CRLSettings()
