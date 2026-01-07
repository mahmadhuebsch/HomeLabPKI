"""Authentication service."""

import logging
import secrets
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import bcrypt

from app.models.auth import Session
from app.models.config import AuthSettings
from app.services.yaml_service import YAMLService

logger = logging.getLogger("homelabpki")

# Default password
DEFAULT_PASSWORD = "adminadmin"


class AuthService:
    """Service for authentication operations."""

    def __init__(self, auth_settings: AuthSettings, config_path: Path = Path("config.yaml")):
        """
        Initialize auth service.

        Args:
            auth_settings: Authentication settings from config
            config_path: Path to config.yaml for updating password hash
        """
        self.settings = auth_settings
        self.config_path = config_path
        self._sessions: dict[str, Session] = {}  # In-memory session store
        self._ensure_password_hash()

    def _ensure_password_hash(self) -> None:
        """Ensure password hash exists, create default if not."""
        if not self.settings.password_hash:
            logger.warning("No password hash found, setting default password 'adminadmin'")
            hash_value = self.hash_password(DEFAULT_PASSWORD)
            self._update_config("password_hash", hash_value)
            self.settings.password_hash = hash_value

    def _update_config(self, key: str, value: str) -> None:
        """Update a single auth config value in config.yaml."""
        try:
            config_data = YAMLService.load_yaml(self.config_path)
            if "auth" not in config_data:
                config_data["auth"] = {}
            config_data["auth"][key] = value
            YAMLService.save_yaml(self.config_path, config_data)
        except Exception as e:
            logger.error(f"Failed to update config: {e}")

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using bcrypt."""
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

    def verify_password(self, password: str) -> bool:
        """Verify a password against the stored hash."""
        if not self.settings.password_hash:
            return False
        try:
            return bcrypt.checkpw(
                password.encode("utf-8"),
                self.settings.password_hash.encode("utf-8"),
            )
        except Exception as e:
            logger.error(f"Password verification failed: {e}")
            return False

    def create_session(
        self,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> Session:
        """Create a new session and return session token."""
        token = str(uuid.uuid4())
        now = datetime.now()
        expires_at = now + timedelta(hours=self.settings.session_expiry_hours)

        session = Session(
            token=token,
            created_at=now,
            expires_at=expires_at,
            user_agent=user_agent,
            ip_address=ip_address,
        )

        self._sessions[token] = session
        self._cleanup_expired_sessions()

        logger.info(f"Session created, expires at {expires_at}")
        return session

    def validate_session(self, token: str) -> Optional[Session]:
        """Validate a session token and return session if valid."""
        session = self._sessions.get(token)
        if not session:
            return None

        if datetime.now() > session.expires_at:
            del self._sessions[token]
            return None

        return session

    def invalidate_session(self, token: str) -> bool:
        """Invalidate a session token."""
        if token in self._sessions:
            del self._sessions[token]
            logger.info("Session invalidated")
            return True
        return False

    def _cleanup_expired_sessions(self) -> None:
        """Remove expired sessions from memory."""
        now = datetime.now()
        expired = [t for t, s in self._sessions.items() if now > s.expires_at]
        for token in expired:
            del self._sessions[token]
        if expired:
            logger.debug(f"Cleaned up {len(expired)} expired sessions")

    def change_password(self, current_password: str, new_password: str) -> bool:
        """Change the password if current password is correct."""
        if not self.verify_password(current_password):
            return False

        new_hash = self.hash_password(new_password)
        self._update_config("password_hash", new_hash)
        self.settings.password_hash = new_hash

        # Invalidate all sessions on password change
        self._sessions.clear()
        logger.info("Password changed, all sessions invalidated")
        return True

    def generate_csrf_token(self) -> str:
        """Generate a CSRF token."""
        return secrets.token_urlsafe(32)

    def validate_csrf_token(self, token: str, cookie_token: str) -> bool:
        """Validate CSRF token using double-submit cookie pattern."""
        if not token or not cookie_token:
            return False
        return secrets.compare_digest(token, cookie_token)

    @property
    def is_enabled(self) -> bool:
        """Check if authentication is enabled."""
        return self.settings.enabled
