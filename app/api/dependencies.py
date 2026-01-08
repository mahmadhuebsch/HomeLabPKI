"""FastAPI dependencies."""

import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from fastapi import Cookie, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.models.auth import Session
from app.models.config import AppConfig
from app.services.auth_service import AuthService
from app.services.ca_service import CAService
from app.services.cert_service import CertificateService
from app.services.csr_service import CSRService
from app.services.openssl_service import OpenSSLService
from app.services.yaml_service import YAMLService
from app.utils.logger import setup_logger

logger = logging.getLogger("homelabpki")

# Global auth service instance (singleton)
_auth_service: Optional[AuthService] = None

# Bearer token security scheme
security = HTTPBearer(auto_error=False)


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
    ca_service = get_ca_service()
    return CertificateService(ca_data_dir, openssl_service, ca_service)


def get_csr_service() -> CSRService:
    """
    Get CSR service instance.

    Returns:
        CSR service
    """
    config = get_config()
    ca_data_dir = Path(config.paths.ca_data)
    openssl_service = get_openssl_service()
    return CSRService(ca_data_dir, openssl_service)


def get_auth_service() -> AuthService:
    """
    Get authentication service instance (singleton).

    Returns:
        Authentication service
    """
    global _auth_service
    if _auth_service is None:
        config = get_config()
        _auth_service = AuthService(config.auth)
    return _auth_service


def reset_auth_service() -> None:
    """Reset the auth service singleton (for testing)."""
    global _auth_service
    _auth_service = None


def get_optional_session(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    session_token: Optional[str] = Cookie(None),
    auth_service: AuthService = Depends(get_auth_service),
) -> Optional[Session]:
    """
    Get session from either Bearer token or cookie.
    Returns None if no valid session found (for optional auth routes).
    """
    if not auth_service.is_enabled:
        return None  # Auth disabled, allow access

    # Try Bearer token first (API clients)
    if credentials and credentials.credentials:
        session = auth_service.validate_session(credentials.credentials)
        if session:
            return session

    # Try session cookie (Web UI)
    if session_token:
        session = auth_service.validate_session(session_token)
        if session:
            return session

    return None


def require_auth(
    session: Optional[Session] = Depends(get_optional_session),
    auth_service: AuthService = Depends(get_auth_service),
) -> Session:
    """
    Require authentication. Raises 401 if not authenticated.
    Use as a dependency on protected routes.
    """
    if not auth_service.is_enabled:
        # Return a dummy session if auth is disabled
        return Session(
            token="disabled",
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(days=365),
        )

    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return session


class AuthRedirect(Exception):
    """Exception to signal redirect to login page."""

    pass


def require_auth_web(
    request: Request,
    session: Optional[Session] = Depends(get_optional_session),
    auth_service: AuthService = Depends(get_auth_service),
) -> Session:
    """
    Require authentication for web routes.
    Redirects to login page if not authenticated (instead of 401).
    """
    if not auth_service.is_enabled:
        # Return a dummy session if auth is disabled
        return Session(
            token="disabled",
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(days=365),
        )

    if not session:
        # Store the original URL for redirect after login
        next_url = str(request.url.path)
        if request.url.query:
            next_url += f"?{request.url.query}"
        raise AuthRedirect(next_url)
    return session
