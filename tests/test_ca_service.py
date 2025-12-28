"""Tests for CA service."""

import pytest
from pathlib import Path

from app.models.ca import CACreateRequest, CAType, Subject, KeyConfig
from app.services.ca_service import CAService


@pytest.mark.unit
class TestCAService:
    """Test CA service operations."""

    def test_create_root_ca(self, ca_service, sample_root_ca_request):
        """Test creating a root CA."""
        ca = ca_service.create_root_ca(sample_root_ca_request)

        assert ca is not None
        assert ca.id.startswith("root-ca-")
        assert ca.subject.common_name == "Test Root CA"
        assert ca.type == CAType.ROOT_CA
        assert Path(ca.path).exists()
        assert (Path(ca.path) / "ca.crt").exists()
        assert (Path(ca.path) / "ca.key").exists()
        assert (Path(ca.path) / "config.yaml").exists()

    def test_create_duplicate_root_ca_fails(self, ca_service, sample_root_ca_request):
        """Test that creating duplicate root CA fails."""
        ca_service.create_root_ca(sample_root_ca_request)

        with pytest.raises(ValueError, match="CA already exists"):
            ca_service.create_root_ca(sample_root_ca_request)

    def test_list_root_cas(self, ca_service, created_root_ca):
        """Test listing root CAs."""
        root_cas = ca_service.list_root_cas()

        assert len(root_cas) == 1
        assert root_cas[0].id == created_root_ca.id

    def test_get_ca(self, ca_service, created_root_ca):
        """Test getting a CA by ID."""
        ca = ca_service.get_ca(created_root_ca.id)

        assert ca.id == created_root_ca.id
        assert ca.subject.common_name == created_root_ca.subject.common_name

    def test_get_nonexistent_ca_fails(self, ca_service):
        """Test that getting nonexistent CA fails."""
        with pytest.raises(ValueError, match="CA not found"):
            ca_service.get_ca("nonexistent-ca")

    def test_create_intermediate_ca(self, ca_service, created_root_ca):
        """Test creating an intermediate CA."""
        request = CACreateRequest(
            type=CAType.INTERMEDIATE_CA,
            subject=Subject(
                common_name="Test Intermediate CA",
                organization="Test Org",
                country="US"
            ),
            key_config=KeyConfig(algorithm="RSA", key_size=2048),
            validity_days=365
        )

        int_ca = ca_service.create_intermediate_ca(request, created_root_ca.id)

        assert int_ca is not None
        assert int_ca.id.startswith(f"{created_root_ca.id}/intermediate-ca-")
        assert int_ca.type == CAType.INTERMEDIATE_CA
        assert Path(int_ca.path).exists()

    def test_create_intermediate_without_parent_fails(self, ca_service):
        """Test that creating intermediate CA without parent fails."""
        request = CACreateRequest(
            type=CAType.INTERMEDIATE_CA,
            subject=Subject(common_name="Test Int CA", country="US"),
            key_config=KeyConfig(algorithm="RSA", key_size=2048),
            validity_days=365
        )

        with pytest.raises(ValueError, match="Parent CA not found"):
            ca_service.create_intermediate_ca(request, "nonexistent-parent")

    def test_list_all_intermediate_cas(self, ca_service, created_intermediate_ca):
        """Test listing all intermediate CAs."""
        intermediates = ca_service.list_all_intermediate_cas()

        assert len(intermediates) >= 1
        assert any(ca.id == created_intermediate_ca.id for ca in intermediates)

    def test_delete_ca(self, ca_service, created_root_ca):
        """Test deleting a CA."""
        ca_id = created_root_ca.id
        ca_path = Path(created_root_ca.path)

        assert ca_path.exists()

        ca_service.delete_ca(ca_id)

        assert not ca_path.exists()
        with pytest.raises(ValueError, match="CA not found"):
            ca_service.get_ca(ca_id)

    def test_get_statistics(self, ca_service, created_root_ca, created_intermediate_ca):
        """Test getting statistics."""
        stats = ca_service.get_statistics()

        assert stats["root_cas"] >= 1
        assert stats["intermediate_cas"] >= 1
        assert "certificates" in stats
        assert "expiring_soon" in stats


@pytest.mark.unit
class TestCAKeyAlgorithms:
    """Test different key algorithms for CAs."""

    def test_create_ca_with_rsa_4096(self, ca_service, sample_ca_subject):
        """Test creating CA with RSA 4096."""
        request = CACreateRequest(
            type=CAType.ROOT_CA,
            subject=sample_ca_subject,
            key_config=KeyConfig(algorithm="RSA", key_size=4096),
            validity_days=365
        )

        ca = ca_service.create_root_ca(request)
        assert ca is not None

    def test_create_ca_with_ecdsa(self, ca_service, sample_ca_subject):
        """Test creating CA with ECDSA."""
        request = CACreateRequest(
            type=CAType.ROOT_CA,
            subject=Subject(
                common_name="ECDSA Test CA",
                organization="Test Org",
                country="US"
            ),
            key_config=KeyConfig(algorithm="ECDSA", curve="P-256"),
            validity_days=365
        )

        ca = ca_service.create_root_ca(request)
        assert ca is not None

    def test_create_ca_with_ed25519(self, ca_service, sample_ca_subject):
        """Test creating CA with Ed25519."""
        request = CACreateRequest(
            type=CAType.ROOT_CA,
            subject=Subject(
                common_name="Ed25519 Test CA",
                organization="Test Org",
                country="US"
            ),
            key_config=KeyConfig(algorithm="Ed25519"),
            validity_days=365
        )

        ca = ca_service.create_root_ca(request)
        assert ca is not None
