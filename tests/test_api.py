"""Tests for API endpoints."""

import pytest
from fastapi import status


@pytest.mark.integration
class TestCAAPI:
    """Test CA API endpoints."""

    def test_health_check(self, client):
        """Test health check endpoint."""
        response = client.get("/health")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data

    def test_list_root_cas(self, client):
        """Test listing root CAs."""
        response = client.get("/api/cas")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert isinstance(data, list)

    def test_create_root_ca(self, client):
        """Test creating a root CA via API."""
        payload = {
            "type": "root_ca",
            "subject": {
                "common_name": "API Test Root CA",
                "organization": "Test Org",
                "country": "US",
            },
            "key_algorithm": "RSA",
            "key_size": 2048,
            "key_password": "test_password_123",
            "validity_days": 365,
        }

        response = client.post("/api/cas", json=payload)

        assert response.status_code == 201  # POST returns 201 Created
        data = response.json()
        assert data["subject"]["common_name"] == "API Test Root CA"
        assert data["type"] == "root_ca"

    def test_get_ca(self, client):
        """Test getting a CA by ID."""
        # First create a CA
        payload = {
            "type": "root_ca",
            "subject": {"common_name": "Get Test CA", "country": "US"},
            "key_algorithm": "RSA",
            "key_size": 2048,
            "key_password": "test_password_123",
            "validity_days": 365,
        }
        create_response = client.post("/api/cas", json=payload)
        assert create_response.status_code == 201
        ca_id = create_response.json()["id"]

        # Now get it
        response = client.get(f"/api/cas/{ca_id}")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["id"] == ca_id

    def test_get_nonexistent_ca(self, client):
        """Test getting nonexistent CA returns 404."""
        response = client.get("/api/cas/nonexistent-ca")

        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_delete_ca(self, client):
        """Test deleting a CA."""
        # First create a CA
        payload = {
            "type": "root_ca",
            "subject": {"common_name": "Delete Test CA", "country": "US"},
            "key_algorithm": "RSA",
            "key_size": 2048,
            "key_password": "test_password_123",
            "validity_days": 365,
        }
        create_response = client.post("/api/cas", json=payload)
        assert create_response.status_code == 201
        ca_id = create_response.json()["id"]

        # Now delete it
        response = client.delete(f"/api/cas/{ca_id}")

        assert response.status_code == 204  # DELETE returns 204 No Content

        # Verify it's gone
        get_response = client.get(f"/api/cas/{ca_id}")
        assert get_response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.integration
class TestCertificateAPI:
    """Test Certificate API endpoints."""

    def test_create_certificate(self, client):
        """Test creating a certificate via API."""
        # First create a CA
        ca_payload = {
            "type": "root_ca",
            "subject": {"common_name": "Cert Test CA", "country": "US"},
            "key_algorithm": "RSA",
            "key_size": 2048,
            "key_password": "test_password_123",
            "validity_days": 365,
        }
        ca_response = client.post("/api/cas", json=ca_payload)
        assert ca_response.status_code == 201
        ca_id = ca_response.json()["id"]

        # Now create a certificate
        cert_payload = {
            "subject": {"common_name": "api-test.com", "country": "US"},
            "sans": ["api-test.com", "*.api-test.com"],
            "key_algorithm": "RSA",
            "key_size": 2048,
            "key_password": "cert_password_123",
            "validity_days": 365,
            "issuing_ca_id": ca_id,
            "issuing_ca_password": "test_password_123",
        }

        response = client.post("/api/certs", json=cert_payload)

        assert response.status_code == 201  # POST returns 201 Created
        data = response.json()
        assert data["subject"]["common_name"] == "api-test.com"

    def test_list_certificates_for_ca(self, client):
        """Test listing certificates for a CA."""
        # Create CA and certificate
        ca_payload = {
            "type": "root_ca",
            "subject": {"common_name": "List Cert CA", "country": "US"},
            "key_algorithm": "RSA",
            "key_size": 2048,
            "key_password": "test_password_123",
            "validity_days": 365,
        }
        ca_response = client.post("/api/cas", json=ca_payload)
        assert ca_response.status_code == 201
        ca_id = ca_response.json()["id"]

        cert_payload = {
            "subject": {"common_name": "list-test.com", "country": "US"},
            "sans": ["list-test.com"],
            "key_algorithm": "RSA",
            "key_size": 2048,
            "key_password": "cert_password_123",
            "validity_days": 365,
            "issuing_ca_id": ca_id,
            "issuing_ca_password": "test_password_123",
        }
        client.post("/api/certs", json=cert_payload)

        # List certificates
        response = client.get(f"/api/certs/{ca_id}/list")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1


@pytest.mark.integration
class TestDownloadAPI:
    """Test download endpoints."""

    def test_download_ca_certificate(self, client):
        """Test downloading CA certificate."""
        # Create CA
        ca_payload = {
            "type": "root_ca",
            "subject": {"common_name": "Download Test CA", "country": "US"},
            "key_algorithm": "RSA",
            "key_size": 2048,
            "key_password": "test_password_123",
            "validity_days": 365,
        }
        ca_response = client.post("/api/cas", json=ca_payload)
        assert ca_response.status_code == 201
        ca_id = ca_response.json()["id"]

        # Download certificate
        response = client.get(f"/download/ca/{ca_id}/cert")

        assert response.status_code == status.HTTP_200_OK
        assert response.headers["content-type"] == "application/x-pem-file"
        assert b"BEGIN CERTIFICATE" in response.content

    def test_download_certificate(self, client):
        """Test downloading server certificate."""
        # Create CA and certificate
        ca_payload = {
            "type": "root_ca",
            "subject": {"common_name": "DL Cert CA", "country": "US"},
            "key_algorithm": "RSA",
            "key_size": 2048,
            "key_password": "test_password_123",
            "validity_days": 365,
        }
        ca_response = client.post("/api/cas", json=ca_payload)
        assert ca_response.status_code == 201
        ca_id = ca_response.json()["id"]

        cert_payload = {
            "subject": {"common_name": "download-test.com", "country": "US"},
            "sans": ["download-test.com"],
            "key_algorithm": "RSA",
            "key_size": 2048,
            "key_password": "cert_password_123",
            "validity_days": 365,
            "issuing_ca_id": ca_id,
            "issuing_ca_password": "test_password_123",
        }
        cert_response = client.post("/api/certs", json=cert_payload)
        cert_id = cert_response.json()["id"]

        # Download certificate
        response = client.get(f"/download/cert/{cert_id}/cert")

        assert response.status_code == status.HTTP_200_OK
        assert b"BEGIN CERTIFICATE" in response.content

    def test_download_fullchain(self, client):
        """Test downloading full certificate chain."""
        # Create CA and certificate
        ca_payload = {
            "type": "root_ca",
            "subject": {"common_name": "Chain CA", "country": "US"},
            "key_algorithm": "RSA",
            "key_size": 2048,
            "key_password": "test_password_123",
            "validity_days": 365,
        }
        ca_response = client.post("/api/cas", json=ca_payload)
        assert ca_response.status_code == 201
        ca_id = ca_response.json()["id"]

        cert_payload = {
            "subject": {"common_name": "chain-test.com", "country": "US"},
            "sans": ["chain-test.com"],
            "key_algorithm": "RSA",
            "key_size": 2048,
            "key_password": "cert_password_123",
            "validity_days": 365,
            "issuing_ca_id": ca_id,
            "issuing_ca_password": "test_password_123",
        }
        cert_response = client.post("/api/certs", json=cert_payload)
        cert_id = cert_response.json()["id"]

        # Download full chain
        response = client.get(f"/download/cert/{cert_id}/fullchain")

        assert response.status_code == status.HTTP_200_OK
        # Should have multiple certificates in the chain
        assert response.content.count(b"BEGIN CERTIFICATE") >= 2
