"""Tests for CA import functionality."""

import pytest
from pathlib import Path
import tempfile

from app.models.ca import RootCAImportRequest, IntermediateCAImportRequest


@pytest.mark.unit
class TestRootCAImport:
    """Test Root CA import functionality."""

    def test_import_root_ca(self, ca_service, created_root_ca):
        """Test importing a Root CA."""
        # Read the created Root CA certificate content
        ca_cert_path = Path(created_root_ca.path) / "ca.crt"
        ca_cert_content = ca_cert_path.read_text()

        # Also read the private key
        ca_key_path = Path(created_root_ca.path) / "ca.key"
        ca_key_content = ca_key_path.read_text()

        # Import the CA
        import_request = RootCAImportRequest(
            ca_cert_content=ca_cert_content, ca_name="imported-root-ca", ca_key_content=ca_key_content
        )

        imported_ca = ca_service.import_root_ca(import_request)

        assert imported_ca is not None
        assert "imported-root-ca" in imported_ca.id
        assert imported_ca.type.value == "root_ca"
        assert Path(imported_ca.path).exists()
        assert (Path(imported_ca.path) / "ca.crt").exists()
        assert (Path(imported_ca.path) / "ca.key").exists()
        assert (Path(imported_ca.path) / "config.yaml").exists()
        assert (Path(imported_ca.path) / "serial").exists()

    def test_import_root_ca_without_key(self, ca_service, created_root_ca):
        """Test importing a Root CA without private key."""
        # Read the created Root CA certificate content
        ca_cert_path = Path(created_root_ca.path) / "ca.crt"
        ca_cert_content = ca_cert_path.read_text()

        # Import the CA without the private key
        import_request = RootCAImportRequest(ca_cert_content=ca_cert_content, ca_name="imported-root-ca-nokey")

        imported_ca = ca_service.import_root_ca(import_request)

        assert imported_ca is not None
        assert "imported-root-ca-nokey" in imported_ca.id
        assert Path(imported_ca.path).exists()
        assert (Path(imported_ca.path) / "ca.crt").exists()
        assert not (Path(imported_ca.path) / "ca.key").exists()  # No key file

    def test_import_duplicate_root_ca_fails(self, ca_service, created_root_ca):
        """Test that importing duplicate Root CA fails."""
        ca_cert_path = Path(created_root_ca.path) / "ca.crt"
        ca_cert_content = ca_cert_path.read_text()

        # Import once
        import_request = RootCAImportRequest(ca_cert_content=ca_cert_content, ca_name="dup-root-ca")
        ca_service.import_root_ca(import_request)

        # Try to import again with same name
        with pytest.raises(ValueError, match="CA already exists"):
            ca_service.import_root_ca(import_request)


@pytest.mark.unit
class TestIntermediateCAImport:
    """Test Intermediate CA import functionality."""

    def test_import_intermediate_ca(self, ca_service, created_root_ca, created_intermediate_ca):
        """Test importing an Intermediate CA."""
        # Read the created Intermediate CA certificate content
        int_ca_cert_path = Path(created_intermediate_ca.path) / "ca.crt"
        int_ca_cert_content = int_ca_cert_path.read_text()

        # Also read the private key
        int_ca_key_path = Path(created_intermediate_ca.path) / "ca.key"
        int_ca_key_content = int_ca_key_path.read_text()

        # Import the Intermediate CA under the same root
        import_request = IntermediateCAImportRequest(
            parent_ca_id=created_root_ca.id,
            ca_cert_content=int_ca_cert_content,
            ca_name="imported-intermediate-ca",
            ca_key_content=int_ca_key_content,
        )

        imported_ca = ca_service.import_intermediate_ca(import_request)

        assert imported_ca is not None
        assert "imported-intermediate-ca" in imported_ca.id
        assert imported_ca.type.value == "intermediate_ca"
        assert Path(imported_ca.path).exists()
        assert (Path(imported_ca.path) / "ca.crt").exists()
        assert (Path(imported_ca.path) / "ca.key").exists()
        assert (Path(imported_ca.path) / "config.yaml").exists()
        assert (Path(imported_ca.path) / "serial").exists()
        assert (Path(imported_ca.path) / "certs").exists()

    def test_import_intermediate_ca_without_key(self, ca_service, created_root_ca, created_intermediate_ca):
        """Test importing an Intermediate CA without private key."""
        # Read the created Intermediate CA certificate content
        int_ca_cert_path = Path(created_intermediate_ca.path) / "ca.crt"
        int_ca_cert_content = int_ca_cert_path.read_text()

        # Import the Intermediate CA without the private key
        import_request = IntermediateCAImportRequest(
            parent_ca_id=created_root_ca.id,
            ca_cert_content=int_ca_cert_content,
            ca_name="imported-intermediate-ca-nokey",
        )

        imported_ca = ca_service.import_intermediate_ca(import_request)

        assert imported_ca is not None
        assert "imported-intermediate-ca-nokey" in imported_ca.id
        assert Path(imported_ca.path).exists()
        assert (Path(imported_ca.path) / "ca.crt").exists()
        assert not (Path(imported_ca.path) / "ca.key").exists()  # No key file

    def test_import_intermediate_ca_with_invalid_parent_fails(self, ca_service, created_intermediate_ca):
        """Test that importing Intermediate CA with invalid parent fails."""
        int_ca_cert_path = Path(created_intermediate_ca.path) / "ca.crt"
        int_ca_cert_content = int_ca_cert_path.read_text()

        import_request = IntermediateCAImportRequest(
            parent_ca_id="nonexistent-ca", ca_cert_content=int_ca_cert_content, ca_name="test-intermediate"
        )

        with pytest.raises(ValueError, match="Parent CA not found"):
            ca_service.import_intermediate_ca(import_request)

    def test_import_duplicate_intermediate_ca_fails(self, ca_service, created_root_ca, created_intermediate_ca):
        """Test that importing duplicate Intermediate CA fails."""
        int_ca_cert_path = Path(created_intermediate_ca.path) / "ca.crt"
        int_ca_cert_content = int_ca_cert_path.read_text()

        # Import once
        import_request = IntermediateCAImportRequest(
            parent_ca_id=created_root_ca.id, ca_cert_content=int_ca_cert_content, ca_name="dup-intermediate-ca"
        )
        ca_service.import_intermediate_ca(import_request)

        # Try to import again with same name
        with pytest.raises(ValueError, match="Intermediate CA already exists"):
            ca_service.import_intermediate_ca(import_request)


@pytest.mark.integration
class TestCAImportAPI:
    """Test CA import API endpoints."""

    def test_import_root_ca_endpoint(self, client, created_root_ca):
        """Test Root CA import API endpoint."""
        # Read the created Root CA certificate content
        ca_cert_path = Path(created_root_ca.path) / "ca.crt"
        ca_cert_content = ca_cert_path.read_text()

        payload = {"ca_cert_content": ca_cert_content, "ca_name": "api-imported-root-ca"}

        response = client.post("/api/cas/import-root", json=payload)

        assert response.status_code == 201
        data = response.json()
        assert "api-imported-root-ca" in data["id"]
        assert data["type"] == "root_ca"

    def test_import_root_ca_endpoint_with_key(self, client, created_root_ca):
        """Test Root CA import API endpoint with private key."""
        ca_cert_path = Path(created_root_ca.path) / "ca.crt"
        ca_cert_content = ca_cert_path.read_text()

        ca_key_path = Path(created_root_ca.path) / "ca.key"
        ca_key_content = ca_key_path.read_text()

        payload = {
            "ca_cert_content": ca_cert_content,
            "ca_name": "api-imported-root-ca-with-key",
            "ca_key_content": ca_key_content,
        }

        response = client.post("/api/cas/import-root", json=payload)

        assert response.status_code == 201
        data = response.json()
        assert "api-imported-root-ca-with-key" in data["id"]

    def test_import_intermediate_ca_endpoint(self, client, created_root_ca, created_intermediate_ca):
        """Test Intermediate CA import API endpoint."""
        int_ca_cert_path = Path(created_intermediate_ca.path) / "ca.crt"
        int_ca_cert_content = int_ca_cert_path.read_text()

        payload = {
            "parent_ca_id": created_root_ca.id,
            "ca_cert_content": int_ca_cert_content,
            "ca_name": "api-imported-intermediate-ca",
        }

        response = client.post("/api/cas/import-intermediate", json=payload)

        assert response.status_code == 201
        data = response.json()
        assert "api-imported-intermediate-ca" in data["id"]
        assert data["type"] == "intermediate_ca"

    def test_import_intermediate_ca_endpoint_with_invalid_parent(self, client, created_intermediate_ca):
        """Test Intermediate CA import with invalid parent."""
        int_ca_cert_path = Path(created_intermediate_ca.path) / "ca.crt"
        int_ca_cert_content = int_ca_cert_path.read_text()

        payload = {
            "parent_ca_id": "invalid-parent",
            "ca_cert_content": int_ca_cert_content,
            "ca_name": "test-intermediate",
        }

        response = client.post("/api/cas/import-intermediate", json=payload)

        assert response.status_code == 400
