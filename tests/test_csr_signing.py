"""Tests for CSR signing and external certificate import functionality."""

import pytest
from pathlib import Path
import tempfile
import subprocess

from app.models.certificate import CSRSignRequest, CertImportRequest
from app.models.ca import Subject, KeyConfig


@pytest.fixture
def sample_csr():
    """Generate a sample CSR for testing."""
    # Generate a private key and CSR using OpenSSL
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        key_file = tmpdir / "test.key"
        csr_file = tmpdir / "test.csr"

        # Generate RSA key
        subprocess.run(
            f"openssl genrsa -out {key_file} 2048",
            shell=True,
            capture_output=True,
            check=True
        )

        # Generate CSR
        subprocess.run(
            f'openssl req -new -key {key_file} -out {csr_file} '
            f'-subj "/C=US/O=Test Org/CN=csr-test.example.com" '
            f'-addext "subjectAltName=DNS:csr-test.example.com,DNS:*.csr-test.example.com"',
            shell=True,
            capture_output=True,
            check=True
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
        assert 'subject' in csr_info
        assert 'sans' in csr_info
        assert 'public_key' in csr_info

        # Check subject
        assert csr_info['subject']['CN'] == 'csr-test.example.com'
        assert csr_info['subject']['O'] == 'Test Org'
        assert csr_info['subject']['C'] == 'US'

        # Check SANs
        assert 'csr-test.example.com' in csr_info['sans']
        assert '*.csr-test.example.com' in csr_info['sans']

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
            validity_days=365
        )

        cert = cert_service.sign_csr(request)

        assert cert is not None
        assert cert.subject.common_name == "csr-test.example.com"
        assert cert.source == "external"
        assert "csr-test.example.com" in cert.sans
        assert "*.csr-test.example.com" in cert.sans
        assert Path(cert.path).exists()
        assert (Path(cert.path) / "cert.crt").exists()
        assert (Path(cert.path) / "cert.csr").exists()  # CSR should be saved
        assert not (Path(cert.path) / "cert.key").exists()  # No private key

    def test_sign_csr_with_override_sans(self, cert_service, created_root_ca, sample_csr):
        """Test signing a CSR with overridden SANs."""
        request = CSRSignRequest(
            issuing_ca_id=created_root_ca.id,
            csr_content=sample_csr,
            sans=["override.example.com", "*.override.example.com"],
            validity_days=365
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
            validity_days=365
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
            validity_days=365
        )

        with pytest.raises(ValueError):
            cert_service.sign_csr(request)


@pytest.mark.unit
class TestCertificateImport:
    """Test external certificate import functionality."""

    def test_import_certificate(self, cert_service, created_root_ca):
        """Test importing an external certificate."""
        # First create a certificate to get valid cert content
        from app.models.certificate import CertCreateRequest

        # Create a regular certificate first
        create_request = CertCreateRequest(
            subject=Subject(common_name="import-source.com", country="US"),
            sans=["import-source.com"],
            key_config=KeyConfig(algorithm="RSA", key_size=2048),
            validity_days=365,
            issuing_ca_id=created_root_ca.id
        )

        created_cert = cert_service.create_server_certificate(create_request)
        cert_path = Path(created_cert.path) / "cert.crt"
        cert_content = cert_path.read_text()

        # Now import it as external certificate
        import_request = CertImportRequest(
            issuing_ca_id=created_root_ca.id,
            cert_content=cert_content,
            cert_name="imported-certificate"
        )

        imported_cert = cert_service.import_certificate(import_request)

        assert imported_cert is not None
        assert imported_cert.source == "external"
        assert imported_cert.subject.common_name == "import-source.com"
        assert "import-source.com" in imported_cert.sans
        assert Path(imported_cert.path).exists()
        assert (Path(imported_cert.path) / "cert.crt").exists()
        assert not (Path(imported_cert.path) / "cert.key").exists()  # No private key

    def test_import_certificate_with_invalid_ca_fails(self, cert_service):
        """Test that importing with invalid CA fails."""
        request = CertImportRequest(
            issuing_ca_id="nonexistent-ca",
            cert_content="-----BEGIN CERTIFICATE-----\nVALID CERT\n-----END CERTIFICATE-----",
            cert_name="test-import"
        )

        with pytest.raises(ValueError, match="Issuing CA not found"):
            cert_service.import_certificate(request)

    def test_import_duplicate_certificate_fails(self, cert_service, created_root_ca):
        """Test that importing duplicate certificate fails."""
        # Create a certificate first
        from app.models.certificate import CertCreateRequest

        create_request = CertCreateRequest(
            subject=Subject(common_name="duplicate.com", country="US"),
            sans=["duplicate.com"],
            key_config=KeyConfig(algorithm="RSA", key_size=2048),
            validity_days=365,
            issuing_ca_id=created_root_ca.id
        )

        created_cert = cert_service.create_server_certificate(create_request)
        cert_path = Path(created_cert.path) / "cert.crt"
        cert_content = cert_path.read_text()

        # Import once
        import_request = CertImportRequest(
            issuing_ca_id=created_root_ca.id,
            cert_content=cert_content,
            cert_name="import-dup"
        )
        cert_service.import_certificate(import_request)

        # Try to import again with same name
        with pytest.raises(ValueError, match="Certificate already exists"):
            cert_service.import_certificate(import_request)


@pytest.mark.integration
class TestCSRSigningAPI:
    """Test CSR signing API endpoints."""

    def test_sign_csr_endpoint(self, client, created_root_ca, sample_csr):
        """Test CSR signing API endpoint."""
        payload = {
            "issuing_ca_id": created_root_ca.id,
            "csr_content": sample_csr,
            "sans": [],
            "validity_days": 365
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
            "validity_days": 365
        }

        response = client.post("/api/certs/sign-csr", json=payload)

        assert response.status_code == 400


@pytest.mark.integration
class TestCertificateImportAPI:
    """Test certificate import API endpoints."""

    def test_import_certificate_endpoint(self, client, created_root_ca):
        """Test certificate import API endpoint."""
        # First create a certificate to get valid cert content
        cert_payload = {
            "subject": {"common_name": "api-import.com", "country": "US"},
            "sans": ["api-import.com"],
            "key_config": {"algorithm": "RSA", "key_size": 2048},
            "validity_days": 365,
            "issuing_ca_id": created_root_ca.id
        }

        cert_response = client.post("/api/certs", json=cert_payload)
        assert cert_response.status_code == 201

        # Read the certificate content
        cert_path = Path(cert_response.json()["path"]) / "cert.crt"
        cert_content = cert_path.read_text()

        # Import it
        import_payload = {
            "issuing_ca_id": created_root_ca.id,
            "cert_content": cert_content,
            "cert_name": "imported-via-api"
        }

        response = client.post("/api/certs/import", json=import_payload)

        assert response.status_code == 201
        data = response.json()
        assert data["source"] == "external"
        assert data["subject"]["common_name"] == "api-import.com"

    def test_import_certificate_endpoint_with_invalid_ca(self, client):
        """Test certificate import with invalid CA."""
        payload = {
            "issuing_ca_id": "invalid-ca",
            "cert_content": "-----BEGIN CERTIFICATE-----\nVALID\n-----END CERTIFICATE-----",
            "cert_name": "test"
        }

        response = client.post("/api/certs/import", json=payload)

        assert response.status_code == 400
