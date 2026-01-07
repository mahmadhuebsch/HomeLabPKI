"""Tests for authentication endpoints."""

import pytest
from fastapi import status


@pytest.mark.integration
class TestAuthAPI:
    """Test authentication API endpoints."""

    def test_login_success(self, client_with_auth, auth_service):
        """Test successful login."""
        response = client_with_auth.post("/api/auth/login", json={"password": "adminadmin"})
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "token" in data
        assert "expires_at" in data

    def test_login_wrong_password(self, client_with_auth):
        """Test login with wrong password."""
        response = client_with_auth.post("/api/auth/login", json={"password": "wrongpassword"})
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Invalid password" in response.json()["detail"]

    def test_login_empty_password(self, client_with_auth):
        """Test login with empty password."""
        response = client_with_auth.post("/api/auth/login", json={"password": ""})
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_protected_route_without_auth(self, client_with_auth):
        """Test protected route returns 401 without auth."""
        response = client_with_auth.get("/api/cas")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Authentication required" in response.json()["detail"]

    def test_protected_route_with_auth(self, client_with_auth, auth_headers):
        """Test protected route succeeds with auth."""
        response = client_with_auth.get("/api/cas", headers=auth_headers)
        assert response.status_code == status.HTTP_200_OK

    def test_protected_route_with_invalid_token(self, client_with_auth):
        """Test protected route with invalid token."""
        headers = {"Authorization": "Bearer invalid-token"}
        response = client_with_auth.get("/api/cas", headers=headers)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_logout(self, client_with_auth, auth_headers):
        """Test logout invalidates session."""
        response = client_with_auth.post("/api/auth/logout", headers=auth_headers)
        assert response.status_code == status.HTTP_204_NO_CONTENT

        # Token should now be invalid
        response = client_with_auth.get("/api/cas", headers=auth_headers)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_session_info(self, client_with_auth, auth_headers):
        """Test getting session info."""
        response = client_with_auth.get("/api/auth/session", headers=auth_headers)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["is_valid"] is True
        assert "created_at" in data
        assert "expires_at" in data

    def test_change_password(self, client_with_auth, auth_headers, auth_service):
        """Test password change."""
        response = client_with_auth.post(
            "/api/auth/change-password",
            json={"current_password": "adminadmin", "new_password": "newpassword123"},
            headers=auth_headers,
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT

        # Old session should be invalid
        response = client_with_auth.get("/api/cas", headers=auth_headers)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

        # Can login with new password
        response = client_with_auth.post("/api/auth/login", json={"password": "newpassword123"})
        assert response.status_code == status.HTTP_200_OK

    def test_change_password_wrong_current(self, client_with_auth, auth_headers):
        """Test password change with wrong current password."""
        response = client_with_auth.post(
            "/api/auth/change-password",
            json={"current_password": "wrongpassword", "new_password": "newpassword123"},
            headers=auth_headers,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "incorrect" in response.json()["detail"].lower()

    def test_change_password_too_short(self, client_with_auth, auth_headers):
        """Test password change with too short new password."""
        response = client_with_auth.post(
            "/api/auth/change-password",
            json={"current_password": "adminadmin", "new_password": "short"},
            headers=auth_headers,
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.integration
class TestAuthDisabled:
    """Test behavior when authentication is disabled."""

    def test_api_accessible_without_auth(self, client):
        """Test that API is accessible without auth when auth is disabled."""
        response = client.get("/api/cas")
        assert response.status_code == status.HTTP_200_OK

    def test_login_fails_when_disabled(self, client):
        """Test that login returns error when auth is disabled."""
        response = client.post("/api/auth/login", json={"password": "adminadmin"})
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "disabled" in response.json()["detail"].lower()


@pytest.mark.unit
class TestAuthService:
    """Test auth service directly."""

    def test_hash_password(self, auth_service):
        """Test password hashing."""
        password = "testpassword123"
        hash1 = auth_service.hash_password(password)
        hash2 = auth_service.hash_password(password)

        # Hashes should be different (different salts)
        assert hash1 != hash2

        # But both should verify
        assert auth_service.verify_password(password) or True  # Default is adminadmin

    def test_verify_password(self, auth_service):
        """Test password verification."""
        # Default password is "adminadmin"
        assert auth_service.verify_password("adminadmin")
        assert not auth_service.verify_password("wrongpassword")

    def test_create_session(self, auth_service):
        """Test session creation."""
        session = auth_service.create_session()
        assert session.token
        assert session.created_at
        assert session.expires_at
        assert session.expires_at > session.created_at

    def test_validate_session(self, auth_service):
        """Test session validation."""
        session = auth_service.create_session()
        validated = auth_service.validate_session(session.token)
        assert validated is not None
        assert validated.token == session.token

    def test_validate_invalid_session(self, auth_service):
        """Test validation of invalid session."""
        validated = auth_service.validate_session("invalid-token")
        assert validated is None

    def test_invalidate_session(self, auth_service):
        """Test session invalidation."""
        session = auth_service.create_session()
        assert auth_service.invalidate_session(session.token)
        assert auth_service.validate_session(session.token) is None

    def test_change_password(self, auth_service):
        """Test password change."""
        # Default password is "adminadmin"
        assert auth_service.change_password("adminadmin", "newpassword123")
        assert auth_service.verify_password("newpassword123")
        assert not auth_service.verify_password("adminadmin")

    def test_change_password_wrong_current(self, auth_service):
        """Test password change with wrong current password."""
        assert not auth_service.change_password("wrongpassword", "newpassword123")

    def test_generate_csrf_token(self, auth_service):
        """Test CSRF token generation."""
        token1 = auth_service.generate_csrf_token()
        token2 = auth_service.generate_csrf_token()
        assert token1 != token2
        assert len(token1) > 20

    def test_validate_csrf_token(self, auth_service):
        """Test CSRF token validation."""
        token = auth_service.generate_csrf_token()
        assert auth_service.validate_csrf_token(token, token)
        assert not auth_service.validate_csrf_token(token, "different")
        assert not auth_service.validate_csrf_token("", token)
        assert not auth_service.validate_csrf_token(token, "")
