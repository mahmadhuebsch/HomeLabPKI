"""Tests for CRL service."""

from datetime import datetime
from pathlib import Path

import pytest

from app.models.ca import KeyAlgorithm, Subject
from app.models.certificate import CertCreateRequest
from app.models.crl import RevocationReason


@pytest.fixture
def crl_service(ca_data_dir, openssl_service):
    """Create CRL service instance with test directory."""
    from app.services.crl_service import CRLService

    return CRLService(ca_data_dir, openssl_service)


@pytest.mark.unit
class TestCRLService:
    """Test CRL service operations."""

    def test_initialize_crl_files(self, crl_service, created_root_ca, ca_data_dir):
        """Test CRL file initialization."""
        ca_dir = ca_data_dir / created_root_ca.id
        crl_service.initialize_crl_files(ca_dir)

        assert (ca_dir / "index.txt").exists()
        assert (ca_dir / "index.txt.attr").exists()
        assert (ca_dir / "crlnumber").exists()
        assert (ca_dir / "crl").is_dir()
        assert (ca_dir / "crl" / "config.yaml").exists()

    def test_revoke_certificate(self, crl_service, cert_service, created_root_ca):
        """Test revoking a certificate."""
        # Create a certificate
        request = CertCreateRequest(
            subject=Subject(common_name="revoke-test.com", country="US"),
            sans=["revoke-test.com"],
            key_algorithm=KeyAlgorithm.RSA,
            key_size=2048,
            key_password="cert_password_123",
            validity_days=365,
            issuing_ca_id=created_root_ca.id,
            issuing_ca_password="test_password_123",
        )
        cert = cert_service.create_server_certificate(request)

        # Revoke the certificate
        crl_response = crl_service.revoke_certificate(
            cert_id=cert.id,
            ca_password="test_password_123",
            reason=RevocationReason.KEY_COMPROMISE,
        )

        assert crl_response.revoked_count == 1

        # Verify certificate is marked as revoked
        updated_cert = cert_service.get_certificate(cert.id)
        assert updated_cert.revoked is True
        assert updated_cert.revocation_reason == "keyCompromise"

    def test_revoke_already_revoked_fails(self, crl_service, cert_service, created_root_ca):
        """Test that revoking an already revoked certificate fails."""
        request = CertCreateRequest(
            subject=Subject(common_name="double-revoke.com", country="US"),
            sans=["double-revoke.com"],
            key_algorithm=KeyAlgorithm.RSA,
            key_size=2048,
            key_password="cert_password_123",
            validity_days=365,
            issuing_ca_id=created_root_ca.id,
            issuing_ca_password="test_password_123",
        )
        cert = cert_service.create_server_certificate(request)
        crl_service.revoke_certificate(cert.id, "test_password_123")

        with pytest.raises(ValueError, match="already revoked"):
            crl_service.revoke_certificate(cert.id, "test_password_123")

    def test_unrevoke_certificate_hold(self, crl_service, cert_service, created_root_ca):
        """Test unrevoking a certificate with certificateHold reason."""
        request = CertCreateRequest(
            subject=Subject(common_name="hold-test.com", country="US"),
            sans=["hold-test.com"],
            key_algorithm=KeyAlgorithm.RSA,
            key_size=2048,
            key_password="cert_password_123",
            validity_days=365,
            issuing_ca_id=created_root_ca.id,
            issuing_ca_password="test_password_123",
        )
        cert = cert_service.create_server_certificate(request)

        # Revoke with certificateHold
        crl_service.revoke_certificate(cert.id, "test_password_123", RevocationReason.CERTIFICATE_HOLD)

        # Unrevoke
        crl_response = crl_service.unrevoke_certificate(cert.id, "test_password_123")
        assert crl_response.revoked_count == 0

        # Verify certificate is no longer revoked
        updated_cert = cert_service.get_certificate(cert.id)
        assert updated_cert.revoked is False

    def test_unrevoke_non_hold_fails(self, crl_service, cert_service, created_root_ca):
        """Test that unrevoking a non-hold certificate fails."""
        request = CertCreateRequest(
            subject=Subject(common_name="non-hold.com", country="US"),
            sans=["non-hold.com"],
            key_algorithm=KeyAlgorithm.RSA,
            key_size=2048,
            key_password="cert_password_123",
            validity_days=365,
            issuing_ca_id=created_root_ca.id,
            issuing_ca_password="test_password_123",
        )
        cert = cert_service.create_server_certificate(request)

        # Revoke with keyCompromise (not hold)
        crl_service.revoke_certificate(cert.id, "test_password_123", RevocationReason.KEY_COMPROMISE)

        # Try to unrevoke - should fail
        with pytest.raises(ValueError, match="certificateHold"):
            crl_service.unrevoke_certificate(cert.id, "test_password_123")

    def test_generate_crl(self, crl_service, created_root_ca, ca_data_dir):
        """Test CRL generation."""
        crl_response = crl_service.generate_crl(
            ca_id=created_root_ca.id,
            ca_password="test_password_123",
        )

        assert crl_response.crl_number >= 1
        assert crl_response.next_update > datetime.now()

        # Verify CRL files exist
        ca_dir = ca_data_dir / created_root_ca.id
        assert (ca_dir / "crl" / "crl.pem").exists()
        assert (ca_dir / "crl" / "crl.der").exists()

    def test_invalid_ca_password_fails(self, crl_service, cert_service, created_root_ca):
        """Test that invalid CA password fails revocation."""
        request = CertCreateRequest(
            subject=Subject(common_name="bad-pass.com", country="US"),
            sans=["bad-pass.com"],
            key_algorithm=KeyAlgorithm.RSA,
            key_size=2048,
            key_password="cert_password_123",
            validity_days=365,
            issuing_ca_id=created_root_ca.id,
            issuing_ca_password="test_password_123",
        )
        cert = cert_service.create_server_certificate(request)

        with pytest.raises(ValueError, match="Invalid CA password"):
            crl_service.revoke_certificate(cert.id, "wrong_password")

    def test_list_revoked_certificates(self, crl_service, cert_service, created_root_ca):
        """Test listing revoked certificates."""
        # Create and revoke two certificates
        for i in range(2):
            request = CertCreateRequest(
                subject=Subject(common_name=f"list-test-{i}.com", country="US"),
                sans=[f"list-test-{i}.com"],
                key_algorithm=KeyAlgorithm.RSA,
                key_size=2048,
                key_password="cert_password_123",
                validity_days=365,
                issuing_ca_id=created_root_ca.id,
                issuing_ca_password="test_password_123",
            )
            cert = cert_service.create_server_certificate(request)
            crl_service.revoke_certificate(cert.id, "test_password_123")

        revoked = crl_service.list_revoked_certificates(created_root_ca.id)
        assert len(revoked) == 2


@pytest.mark.integration
class TestCRLAPI:
    """Test CRL API endpoints."""

    def test_revoke_certificate_api(self, client, created_root_ca, cert_service):
        """Test revoking a certificate via API."""
        # Create certificate first
        request = CertCreateRequest(
            subject=Subject(common_name="api-revoke.com", country="US"),
            sans=["api-revoke.com"],
            key_algorithm=KeyAlgorithm.RSA,
            key_size=2048,
            key_password="cert_password_123",
            validity_days=365,
            issuing_ca_id=created_root_ca.id,
            issuing_ca_password="test_password_123",
        )
        cert = cert_service.create_server_certificate(request)

        response = client.post(
            f"/api/certs/{cert.id}/revoke", json={"reason": "superseded", "ca_password": "test_password_123"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["revoked_count"] == 1

    def test_get_crl_info_api(self, client, created_root_ca, crl_service):
        """Test getting CRL info via API."""
        # Generate CRL first
        crl_service.generate_crl(created_root_ca.id, "test_password_123")

        response = client.get(f"/api/cas/{created_root_ca.id}/crl")

        assert response.status_code == 200
        data = response.json()
        assert data["ca_id"] == created_root_ca.id

    def test_download_crl_pem(self, client, created_root_ca, crl_service):
        """Test downloading CRL in PEM format."""
        crl_service.generate_crl(created_root_ca.id, "test_password_123")

        response = client.get(f"/download/ca/{created_root_ca.id}/crl")

        assert response.status_code == 200
        assert b"-----BEGIN X509 CRL-----" in response.content

    def test_download_crl_der(self, client, created_root_ca, crl_service):
        """Test downloading CRL in DER format."""
        crl_service.generate_crl(created_root_ca.id, "test_password_123")

        response = client.get(f"/download/ca/{created_root_ca.id}/crl/der")

        assert response.status_code == 200
        # DER format starts with specific bytes
        assert len(response.content) > 0

    def test_initialize_crl_regenerates_openssl_config(self, ca_service, crl_service, ca_data_dir):
        """Test that initializing CRL regenerates old openssl.cnf without [ca] section."""
        from app.models.ca import CACreateRequest, CAType, KeyAlgorithm, Subject
        from app.utils.file_utils import FileUtils

        # Create a CA
        request = CACreateRequest(
            type=CAType.ROOT_CA,
            subject=Subject(common_name="Old CA", organization="Test", country="US"),
            key_algorithm=KeyAlgorithm.RSA,
            key_size=2048,
            key_password="test_password",
            validity_days=365,
        )
        ca = ca_service.create_root_ca(request)
        ca_dir = ca_data_dir / ca.id

        # Simulate an old openssl.cnf without [ca] section
        old_config = """[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[ req_distinguished_name ]

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
"""
        openssl_cnf = ca_dir / "openssl.cnf"
        FileUtils.write_file(openssl_cnf, old_config)

        # Verify old config doesn't have [ca] section
        content = FileUtils.read_file(openssl_cnf)
        assert "[ ca ]" not in content and "[ca]" not in content

        # Initialize CRL - should regenerate openssl.cnf
        crl_service.initialize_crl_files(ca_dir)

        # Verify new config has [ca] section (with or without spaces)
        content = FileUtils.read_file(openssl_cnf)
        assert "[ ca ]" in content or "[ca]" in content
        assert "default_ca = CA_default" in content
        assert "[ CA_default ]" in content
        assert "database" in content
        assert "crlnumber" in content

        # Verify CRL can now be generated
        crl_response = crl_service.generate_crl(ca.id, "test_password")
        assert crl_response.ca_id == ca.id
