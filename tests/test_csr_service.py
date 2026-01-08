"""Tests for CSR service."""

from pathlib import Path

import pytest

from app.models.ca import KeyAlgorithm, Subject
from app.models.certificate import CSRCreateRequest, CSRSignedRequest, CSRStatus


@pytest.mark.unit
class TestCSRService:
    """Test CSR service operations."""

    def test_create_csr(self, csr_service):
        """Test creating a CSR."""
        request = CSRCreateRequest(
            subject=Subject(common_name="test.example.com", organization="Test Org", country="US"),
            sans=["test.example.com", "*.test.example.com"],
            key_algorithm=KeyAlgorithm.RSA,
            key_size=2048,
            key_password="csr_password_123",
            target_ca="DigiCert",
        )

        csr = csr_service.create_csr(request)

        assert csr is not None
        assert csr.subject.common_name == "test.example.com"
        assert "test.example.com" in csr.sans
        assert csr.status == CSRStatus.PENDING
        assert csr.target_ca == "DigiCert"
        assert Path(csr.path).exists()
        assert (Path(csr.path) / "csr.pem").exists()
        assert (Path(csr.path) / "key.pem").exists()

    def test_create_csr_with_ecdsa(self, csr_service):
        """Test creating a CSR with ECDSA key."""
        request = CSRCreateRequest(
            subject=Subject(common_name="ecdsa.example.com", country="US"),
            sans=["ecdsa.example.com"],
            key_algorithm=KeyAlgorithm.ECDSA,
            key_curve="P-256",
            key_password="csr_password_123",
        )

        csr = csr_service.create_csr(request)

        assert csr is not None
        assert csr.subject.common_name == "ecdsa.example.com"
        assert csr.status == CSRStatus.PENDING

    def test_create_csr_with_ed25519(self, csr_service):
        """Test creating a CSR with Ed25519 key."""
        request = CSRCreateRequest(
            subject=Subject(common_name="ed25519.example.com", country="US"),
            sans=["ed25519.example.com"],
            key_algorithm=KeyAlgorithm.ED25519,
            key_password="csr_password_123",
        )

        csr = csr_service.create_csr(request)

        assert csr is not None
        assert csr.subject.common_name == "ed25519.example.com"
        assert csr.status == CSRStatus.PENDING

    def test_create_duplicate_csr_fails(self, csr_service):
        """Test that creating duplicate CSR fails."""
        request = CSRCreateRequest(
            subject=Subject(common_name="duplicate.com", country="US"),
            sans=["duplicate.com"],
            key_algorithm=KeyAlgorithm.RSA,
            key_size=2048,
            key_password="csr_password_123",
        )

        csr_service.create_csr(request)

        with pytest.raises(ValueError, match="CSR already exists"):
            csr_service.create_csr(request)

    def test_get_csr(self, csr_service):
        """Test getting a CSR by ID."""
        request = CSRCreateRequest(
            subject=Subject(common_name="get-test.com", country="US"),
            sans=["get-test.com"],
            key_algorithm=KeyAlgorithm.RSA,
            key_size=2048,
            key_password="csr_password_123",
        )

        created_csr = csr_service.create_csr(request)
        retrieved_csr = csr_service.get_csr(created_csr.id)

        assert retrieved_csr.id == created_csr.id
        assert retrieved_csr.subject.common_name == "get-test.com"
        assert retrieved_csr.status == CSRStatus.PENDING

    def test_get_nonexistent_csr_fails(self, csr_service):
        """Test that getting nonexistent CSR fails."""
        with pytest.raises(ValueError, match="CSR not found"):
            csr_service.get_csr("nonexistent-csr")

    def test_list_csrs(self, csr_service):
        """Test listing all CSRs."""
        # Create two CSRs
        request1 = CSRCreateRequest(
            subject=Subject(common_name="list1.com", country="US"),
            sans=["list1.com"],
            key_algorithm=KeyAlgorithm.RSA,
            key_size=2048,
            key_password="csr_password_123",
        )
        csr_service.create_csr(request1)

        request2 = CSRCreateRequest(
            subject=Subject(common_name="list2.com", country="US"),
            sans=["list2.com"],
            key_algorithm=KeyAlgorithm.RSA,
            key_size=2048,
            key_password="csr_password_123",
        )
        csr_service.create_csr(request2)

        csrs = csr_service.list_csrs()

        assert len(csrs) >= 2
        cn_list = [csr.subject.common_name for csr in csrs]
        assert "list1.com" in cn_list
        assert "list2.com" in cn_list

    def test_list_csrs_with_status_filter(self, csr_service):
        """Test listing CSRs with status filter."""
        request = CSRCreateRequest(
            subject=Subject(common_name="filter-test.com", country="US"),
            sans=["filter-test.com"],
            key_algorithm=KeyAlgorithm.RSA,
            key_size=2048,
            key_password="csr_password_123",
        )
        csr_service.create_csr(request)

        pending_csrs = csr_service.list_csrs(status_filter=CSRStatus.PENDING)

        assert len(pending_csrs) >= 1
        assert all(csr.status == CSRStatus.PENDING for csr in pending_csrs)

    def test_delete_csr(self, csr_service):
        """Test deleting a CSR (soft delete)."""
        request = CSRCreateRequest(
            subject=Subject(common_name="delete-test.com", country="US"),
            sans=["delete-test.com"],
            key_algorithm=KeyAlgorithm.RSA,
            key_size=2048,
            key_password="csr_password_123",
        )

        csr = csr_service.create_csr(request)
        csr_path = Path(csr.path)

        assert csr_path.exists()

        csr_service.delete_csr(csr.id)

        # CSR should be moved to trash
        assert not csr_path.exists()
        trash_dir = csr_service.csrs_dir / "_trash"
        assert trash_dir.exists()

    def test_delete_nonexistent_csr_fails(self, csr_service):
        """Test that deleting nonexistent CSR fails."""
        with pytest.raises(ValueError, match="CSR not found"):
            csr_service.delete_csr("nonexistent-csr")

    def test_get_csr_content(self, csr_service):
        """Test getting CSR PEM content."""
        request = CSRCreateRequest(
            subject=Subject(common_name="content-test.com", country="US"),
            sans=["content-test.com"],
            key_algorithm=KeyAlgorithm.RSA,
            key_size=2048,
            key_password="csr_password_123",
        )

        csr = csr_service.create_csr(request)
        content = csr_service.get_csr_content(csr.id)

        assert "-----BEGIN CERTIFICATE REQUEST-----" in content
        assert "-----END CERTIFICATE REQUEST-----" in content


@pytest.mark.integration
@pytest.mark.requires_openssl
class TestCSRServiceIntegration:
    """Integration tests for CSR service."""

    def test_full_csr_workflow(self, csr_service, created_root_ca, openssl_service):
        """Test complete CSR workflow: create, sign externally, import."""
        # Step 1: Create CSR
        request = CSRCreateRequest(
            subject=Subject(common_name="workflow.example.com", organization="Test Org", country="US"),
            sans=["workflow.example.com", "www.workflow.example.com"],
            key_algorithm=KeyAlgorithm.RSA,
            key_size=2048,
            key_password="csr_password_123",
            target_ca="Test CA",
        )

        csr = csr_service.create_csr(request)
        assert csr.status == CSRStatus.PENDING

        # Step 2: Sign CSR with the root CA (simulating external CA signing)
        csr_path = Path(csr.path) / "csr.pem"
        cert_path = Path(csr.path) / "test_signed_cert.pem"

        csr_content = csr_service.get_csr_content(csr.id)

        # Sign the CSR using our CA (simulating external CA)
        ca_cert = Path(created_root_ca.path) / "ca.crt"
        ca_key = Path(created_root_ca.path) / "ca.key"
        serial = openssl_service.generate_serial_number()

        openssl_service.sign_csr(
            csr_content=csr_content,
            ca_cert=ca_cert,
            ca_key=ca_key,
            serial_number=serial,
            validity_days=365,
            sans=csr.sans,
            output_cert=cert_path,
            ca_password="test_password_123",
        )

        # Step 3: Import signed certificate
        with open(cert_path, "r") as f:
            signed_cert_content = f.read()

        import_request = CSRSignedRequest(cert_content=signed_cert_content)
        updated_csr = csr_service.mark_signed(csr.id, import_request)

        assert updated_csr.status == CSRStatus.SIGNED
        assert (Path(csr.path) / "cert.pem").exists()

    def test_import_mismatched_cert_fails(self, csr_service, created_root_ca, cert_service):
        """Test that importing a certificate that doesn't match CSR fails."""
        # Create CSR
        csr_request = CSRCreateRequest(
            subject=Subject(common_name="mismatch.com", country="US"),
            sans=["mismatch.com"],
            key_algorithm=KeyAlgorithm.RSA,
            key_size=2048,
            key_password="csr_password_123",
        )
        csr = csr_service.create_csr(csr_request)

        # Create a different certificate (not from this CSR)
        from app.models.certificate import CertCreateRequest

        cert_request = CertCreateRequest(
            subject=Subject(common_name="different.com", country="US"),
            sans=["different.com"],
            key_algorithm=KeyAlgorithm.RSA,
            key_size=2048,
            key_password="cert_password_123",
            validity_days=365,
            issuing_ca_id=created_root_ca.id,
            issuing_ca_password="test_password_123",
        )
        cert = cert_service.create_server_certificate(cert_request)

        # Try to import this certificate (should fail - different key)
        cert_path = Path(cert.path) / "cert.crt"
        with open(cert_path, "r") as f:
            cert_content = f.read()

        import_request = CSRSignedRequest(cert_content=cert_content)

        with pytest.raises(ValueError, match="does not match CSR public key"):
            csr_service.mark_signed(csr.id, import_request)
