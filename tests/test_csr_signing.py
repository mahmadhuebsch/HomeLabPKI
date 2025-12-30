"""Tests for CSR signing and external certificate import functionality."""

import subprocess
import tempfile
from pathlib import Path
import shutil

import pytest

from app.models.ca import KeyConfig, Subject
from app.models.certificate import CertImportRequest, CSRSignRequest


@pytest.fixture
def sample_csr():
    """Generate a sample CSR for testing."""
    # Generate a private key and CSR using OpenSSL
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        key_file = tmpdir / "test.key"
        csr_file = tmpdir / "test.csr"

        # Create minimal OpenSSL config for the CSR
        config_file = tmpdir / "openssl.cnf"
        config_content = """
[req]
distinguished_name = req_distinguished_name
req_extensions = req_ext
prompt = no

[req_distinguished_name]
C = US
O = Test Org
CN = csr-test.example.com

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = csr-test.example.com
DNS.2 = *.csr-test.example.com
"""
        config_file.write_text(config_content)

        # Generate RSA key
        subprocess.run(f"openssl genrsa -out {key_file} 2048", shell=True, capture_output=True, check=True)

        # Generate CSR using the config
        subprocess.run(
            f"openssl req -new -key {key_file} -out {csr_file} -config {config_file}",
            shell=True,
            capture_output=True,
            check=True,
        )

        csr_content = csr_file.read_text()

    return csr_content


@pytest.mark.unit
class TestCSRParsing:
    """Test CSR parsing functionality."""

    def test_parse_valid_csr(self, openssl_service, sample_csr):
        """Test parsing a valid CSR."""
        csr_info = openssl_service.parse_csr(sample_csr)

        assert csr_info is not None
        assert "subject" in csr_info
        assert "sans" in csr_info
        assert "public_key" in csr_info

        # Check subject
        assert csr_info["subject"]["CN"] == "csr-test.example.com"
        assert csr_info["subject"]["O"] == "Test Org"
        assert csr_info["subject"]["C"] == "US"

        # Check SANs
        assert "csr-test.example.com" in csr_info["sans"]
        assert "*.csr-test.example.com" in csr_info["sans"]

    def test_parse_invalid_csr_fails(self, openssl_service):
        """Test that parsing invalid CSR fails."""
        invalid_csr = "-----BEGIN CERTIFICATE REQUEST-----\nINVALID\n-----END CERTIFICATE REQUEST-----"

        with pytest.raises(ValueError, match="Failed to parse CSR"):
            openssl_service.parse_csr(invalid_csr)


@pytest.mark.unit
class TestCSRSigning:
    """Test CSR signing functionality."""

    def test_sign_csr(self, cert_service, created_root_ca, sample_csr):
        """Test signing a CSR."""
        request = CSRSignRequest(
            issuing_ca_id=created_root_ca.id,
            csr_content=sample_csr,
            sans=[],  # Use SANs from CSR
            validity_days=365,
            issuing_ca_password="test_password_123",
        )

        cert = cert_service.sign_csr(request)

        assert cert is not None
        assert cert.subject.common_name == "csr-test.example.com"
        assert cert.source == "external"
        assert "csr-test.example.com" in cert.sans
        assert "*.csr-test.example.com" in cert.sans
        assert Path(cert.path).exists()
        assert (Path(cert.path) / "cert.crt").exists()
        assert (Path(cert.path) / "cert.csr").exists()
        assert not (Path(cert.path) / "cert.key").exists()

    def test_sign_csr_with_override_sans(self, cert_service, created_root_ca, sample_csr):
        """Test signing a CSR with overridden SANs."""
        request = CSRSignRequest(
            issuing_ca_id=created_root_ca.id,
            csr_content=sample_csr,
            sans=["override.example.com", "*.override.example.com"],
            validity_days=365,
            issuing_ca_password="test_password_123",
        )

        cert = cert_service.sign_csr(request)

        assert cert is not None
        assert "override.example.com" in cert.sans
        assert "*.override.example.com" in cert.sans

    def test_sign_csr_with_invalid_ca_fails(self, cert_service, sample_csr):
        """Test that signing CSR with invalid CA fails."""
        request = CSRSignRequest(
            issuing_ca_id="nonexistent-ca",
            csr_content=sample_csr,
            sans=[],
            validity_days=365,
            issuing_ca_password="test_password_123",
        )

        with pytest.raises(ValueError, match="Issuing CA not found"):
            cert_service.sign_csr(request)

    def test_sign_invalid_csr_fails(self, cert_service, created_root_ca):
        """Test that signing invalid CSR fails."""
        invalid_csr = "-----BEGIN CERTIFICATE REQUEST-----\nINVALID\n-----END CERTIFICATE REQUEST-----"

        request = CSRSignRequest(
            issuing_ca_id=created_root_ca.id,
            csr_content=invalid_csr,
            sans=[],
            validity_days=365,
            issuing_ca_password="test_password_123",
        )

        with pytest.raises(ValueError):
            cert_service.sign_csr(request)


@pytest.mark.integration
class TestCSRSigningAPI:
    """Test CSR signing API endpoints."""

    def test_sign_csr_endpoint(self, client, created_root_ca, sample_csr):
        """Test CSR signing API endpoint."""
        payload = {
            "issuing_ca_id": created_root_ca.id,
            "csr_content": sample_csr,
            "sans": [],
            "validity_days": 365,
            "issuing_ca_password": "test_password_123",
        }

        response = client.post("/api/certs/sign-csr", json=payload)

        assert response.status_code == 201
        data = response.json()
        assert data["subject"]["common_name"] == "csr-test.example.com"
        assert data["source"] == "external"

    def test_sign_csr_endpoint_with_invalid_ca(self, client, sample_csr):
        """Test CSR signing with invalid CA."""
        payload = {
            "issuing_ca_id": "invalid-ca",
            "csr_content": sample_csr,
            "sans": [],
            "validity_days": 365,
            "issuing_ca_password": "test_password_123",
        }

        response = client.post("/api/certs/sign-csr", json=payload)

        assert response.status_code == 400


@pytest.mark.integration
class TestCertificateImportAPI:
    """Test certificate import API endpoints."""

    def test_import_certificate_endpoint(self, client, cert_service, created_intermediate_ca, created_root_ca):
        """Test certificate import API endpoint.

        Creates a certificate, then re-imports it with the issuing CA already present.
        """
        from app.models.certificate import CertCreateRequest

        # 1. Create a certificate
        create_request = CertCreateRequest(
            subject=Subject(common_name="api-import.com", country="US"),
            sans=["api-import.com"],
            key_config=KeyConfig(algorithm="RSA", key_size=2048, password="cert_password_123"),
            validity_days=365,
            issuing_ca_id=created_intermediate_ca.id,
            issuing_ca_password="intermediate_password_123",
        )
        created_cert = cert_service.create_server_certificate(create_request)

        # Get just the leaf certificate PEM (not the full chain)
        cert_path = Path(created_cert.path) / "cert.crt"
        leaf_cert_pem = cert_path.read_text()

        # 2. Delete the created cert directory to simulate fresh import
        shutil.rmtree(Path(created_cert.path))

        # 3. Import via API - the issuing CA (intermediate) already exists
        import_payload = {
            "cert_content": leaf_cert_pem,
            "cert_name": "imported-via-api",
            "issuing_ca_id": created_intermediate_ca.id,
        }

        response = client.post("/api/certs/import", json=import_payload)

        assert response.status_code == 201
        data = response.json()
        assert data["source"] == "external"
        assert data["subject"]["common_name"] == "api-import.com"

    def test_import_certificate_endpoint_with_missing_issuing_ca(self, client):
        """Test certificate import with missing issuing CA ID."""

        payload = {
            "cert_content": "-----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----",
            "cert_name": "test",
            "issuing_ca_id": "",
        }

        response = client.post("/api/certs/import", json=payload)

        assert response.status_code == 400
        assert "Issuing CA ID is required" in response.json()["detail"]

    def test_import_certificate_endpoint_with_invalid_cert(self, client, created_intermediate_ca):
        """Test certificate import with an invalid certificate."""

        payload = {
            "cert_content": "-----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----",
            "cert_name": "test",
            "issuing_ca_id": created_intermediate_ca.id,
        }

        response = client.post("/api/certs/import", json=payload)

        assert response.status_code == 400
        assert "Unable to load PEM file" in response.json()["detail"]
