"""FastAPI dependencies."""

import logging
from functools import lru_cache
from pathlib import Path

from app.models.config import AppConfig
from app.services.ca_service import CAService
from app.services.cert_service import CertificateService
from app.services.openssl_service import OpenSSLService
from app.services.yaml_service import YAMLService
from app.utils.logger import setup_logger

logger = logging.getLogger("yacertmanager")


def get_config() -> AppConfig:
    """
    Get application configuration.

    Returns:
        Application configuration
    """
    config_path = Path("config.yaml")
    if not config_path.exists():
        raise RuntimeError("config.yaml not found")

    config_data = YAMLService.load_yaml(config_path)
    return AppConfig(**config_data)


def get_ca_data_dir() -> Path:
    """
    Get CA data directory path.

    Returns:
        Path to CA data directory
    """
    config = get_config()
    return Path(config.paths.ca_data)


def get_openssl_service() -> OpenSSLService:
    """
    Get OpenSSL service instance.

    Returns:
        OpenSSL service
    """
    config = get_config()
    return OpenSSLService(openssl_path=config.paths.openssl)


def get_ca_service() -> CAService:
    """
    Get CA service instance.

    Returns:
        CA service
    """
    config = get_config()
    ca_data_dir = Path(config.paths.ca_data)
    openssl_service = get_openssl_service()
    return CAService(ca_data_dir, openssl_service)


def get_cert_service() -> CertificateService:
    """
    Get certificate service instance.

    Returns:
        Certificate service
    """
    config = get_config()
    ca_data_dir = Path(config.paths.ca_data)
    openssl_service = get_openssl_service()
    return CertificateService(ca_data_dir, openssl_service)
