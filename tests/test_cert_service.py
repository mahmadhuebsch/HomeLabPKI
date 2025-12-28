"""Tests for Certificate service."""

from pathlib import Path

import pytest

from app.models.ca import KeyConfig, Subject
from app.models.certificate import CertCreateRequest


@pytest.mark.unit
class TestCertificateService:
    """Test certificate service operations."""

    def test_create_server_certificate(self, cert_service, created_root_ca):
        """Test creating a server certificate."""
        request = CertCreateRequest(
            subject=Subject(common_name="test.example.com", organization="Test Org", country="US"),
            sans=["test.example.com", "*.test.example.com"],
            key_config=KeyConfig(algorithm="RSA", key_size=2048),
            validity_days=365,
            issuing_ca_id=created_root_ca.id,
        )

        cert = cert_service.create_server_certificate(request)

        assert cert is not None
        assert cert.subject.common_name == "test.example.com"
        assert "test.example.com" in cert.sans
        assert Path(cert.path).exists()
        assert (Path(cert.path) / "cert.crt").exists()
        assert (Path(cert.path) / "cert.key").exists()

    def test_create_certificate_with_invalid_ca_fails(self, cert_service):
        """Test that creating certificate with invalid CA fails."""
        request = CertCreateRequest(
            subject=Subject(common_name="test.com", country="US"),
            sans=["test.com"],
            key_config=KeyConfig(algorithm="RSA", key_size=2048),
            validity_days=365,
            issuing_ca_id="nonexistent-ca",
        )

        with pytest.raises(ValueError, match="Issuing CA not found"):
            cert_service.create_server_certificate(request)

    def test_list_certificates(self, cert_service, created_root_ca):
        """Test listing certificates for a CA."""
        # Create a certificate
        request = CertCreateRequest(
            subject=Subject(common_name="test1.com", country="US"),
            sans=["test1.com"],
            key_config=KeyConfig(algorithm="RSA", key_size=2048),
            validity_days=365,
            issuing_ca_id=created_root_ca.id,
        )
        cert_service.create_server_certificate(request)

        certs = cert_service.list_certificates(created_root_ca.id)

        assert len(certs) == 1
        assert certs[0].subject.common_name == "test1.com"

    def test_list_all_certificates(self, cert_service, created_root_ca):
        """Test listing all certificates across all CAs."""
        # Create a certificate
        request = CertCreateRequest(
            subject=Subject(common_name="global-test.com", country="US"),
            sans=["global-test.com"],
            key_config=KeyConfig(algorithm="RSA", key_size=2048),
            validity_days=365,
            issuing_ca_id=created_root_ca.id,
        )
        cert_service.create_server_certificate(request)

        all_certs = cert_service.list_all_certificates()

        assert len(all_certs) >= 1
        assert any(c.subject.common_name == "global-test.com" for c in all_certs)

    def test_get_certificate(self, cert_service, created_root_ca):
        """Test getting a certificate by ID."""
        request = CertCreateRequest(
            subject=Subject(common_name="get-test.com", country="US"),
            sans=["get-test.com"],
            key_config=KeyConfig(algorithm="RSA", key_size=2048),
            validity_days=365,
            issuing_ca_id=created_root_ca.id,
        )
        created_cert = cert_service.create_server_certificate(request)

        cert = cert_service.get_certificate(created_cert.id)

        assert cert.id == created_cert.id
        assert cert.subject.common_name == "get-test.com"

    def test_delete_certificate(self, cert_service, created_root_ca):
        """Test deleting a certificate."""
        request = CertCreateRequest(
            subject=Subject(common_name="delete-test.com", country="US"),
            sans=["delete-test.com"],
            key_config=KeyConfig(algorithm="RSA", key_size=2048),
            validity_days=365,
            issuing_ca_id=created_root_ca.id,
        )
        cert = cert_service.create_server_certificate(request)
        cert_path = Path(cert.path)

        assert cert_path.exists()

        cert_service.delete_certificate(cert.id)

        assert not cert_path.exists()

    def test_build_certificate_chain(self, cert_service, created_root_ca):
        """Test building certificate chain."""
        request = CertCreateRequest(
            subject=Subject(common_name="chain-test.com", country="US"),
            sans=["chain-test.com"],
            key_config=KeyConfig(algorithm="RSA", key_size=2048),
            validity_days=365,
            issuing_ca_id=created_root_ca.id,
        )
        cert = cert_service.create_server_certificate(request)

        chain = cert_service.build_certificate_chain(cert.id)

        assert chain is not None
        assert "BEGIN CERTIFICATE" in chain
        # Chain should contain both cert and CA cert
        assert chain.count("BEGIN CERTIFICATE") >= 2


@pytest.mark.unit
class TestCertificateSANs:
    """Test certificate SANs functionality."""

    def test_create_certificate_with_multiple_sans(self, cert_service, created_root_ca):
        """Test creating certificate with multiple SANs."""
        request = CertCreateRequest(
            subject=Subject(common_name="multi-san.com", country="US"),
            sans=["multi-san.com", "*.multi-san.com", "www.multi-san.com", "192.168.1.1"],
            key_config=KeyConfig(algorithm="RSA", key_size=2048),
            validity_days=365,
            issuing_ca_id=created_root_ca.id,
        )

        cert = cert_service.create_server_certificate(request)

        assert len(cert.sans) == 4
        assert "multi-san.com" in cert.sans
        assert "*.multi-san.com" in cert.sans

    def test_create_certificate_without_sans(self, cert_service, created_root_ca):
        """Test creating certificate without explicit SANs."""
        request = CertCreateRequest(
            subject=Subject(common_name="no-san.com", country="US"),
            sans=[],
            key_config=KeyConfig(algorithm="RSA", key_size=2048),
            validity_days=365,
            issuing_ca_id=created_root_ca.id,
        )

        cert = cert_service.create_server_certificate(request)

        # Should default to common name
        assert "no-san.com" in cert.sans
