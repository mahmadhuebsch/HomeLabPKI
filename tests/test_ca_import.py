"""
Tests for CA import functionality."""

import shutil
from pathlib import Path
from datetime import datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.models.ca import IntermediateCAImportRequest, RootCAImportRequest


# --- Helper Functions (duplicated for test coherence as requested) ---
def generate_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def generate_cert(subject_name, issuer_name, issuer_key, public_key, ca=False):
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)]))
    builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)]))

    today = datetime.utcnow()
    builder = builder.not_valid_before(today)
    builder = builder.not_valid_after(today + timedelta(days=30))

    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)
    builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)

    cert = builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())
    return cert


def to_pem(obj):
    if isinstance(obj, x509.Certificate):
        return obj.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    return obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


@pytest.fixture
def valid_root_pem():
    """Generates a valid root CA."""
    root_key = generate_key()
    root_cert = generate_cert("Valid Root", "Valid Root", root_key, root_key.public_key(), ca=True)
    return to_pem(root_cert)


@pytest.fixture
def valid_chain_pems():
    """Generates a generated root and intermediate PEM."""
    root_key = generate_key()
    root_cert = generate_cert("Valid Root", "Valid Root", root_key, root_key.public_key(), ca=True)

    int_key = generate_key()
    int_cert = generate_cert("Valid Intermediate", "Valid Root", root_key, int_key.public_key(), ca=True)

    return to_pem(root_cert), to_pem(int_cert)


@pytest.mark.unit
class TestRootCAImport:
    """Test Root CA import functionality."""

    def test_import_root_ca(self, ca_service, valid_root_pem):
        """Test importing a Root CA (as a single cert chain)."""
        ca_cert_content = valid_root_pem

        if ca_service.ca_data_dir.exists():
            shutil.rmtree(ca_service.ca_data_dir)
        ca_service.ca_data_dir.mkdir()

        import_request = RootCAImportRequest(
            ca_cert_content=ca_cert_content,
            ca_name="imported-root-ca",
        )

        imported_ca = ca_service.import_root_ca(import_request)

        assert imported_ca is not None
        assert "imported-root-ca" in imported_ca.id
        assert imported_ca.type.value == "root_ca"
        assert Path(imported_ca.path).exists()
        assert (Path(imported_ca.path) / "ca.crt").exists()
        assert not (Path(imported_ca.path) / "ca.key").exists()
        assert (Path(imported_ca.path) / "config.yaml").exists()
        assert (Path(imported_ca.path) / "serial").exists()


@pytest.mark.integration
class TestCAImportAPI:
    """Test CA import API endpoints."""

    def test_import_root_ca_endpoint(self, client, ca_data_dir, valid_root_pem):
        """Test Root CA import API endpoint."""
        ca_cert_content = valid_root_pem

        if ca_data_dir.exists():
            shutil.rmtree(ca_data_dir)
        ca_data_dir.mkdir()

        payload = {"ca_cert_content": ca_cert_content, "ca_name": "api-imported-root-ca"}
        response = client.post("/api/cas/import-root", json=payload)

        assert response.status_code == 201
        data = response.json()
        assert "api-imported-root-ca" in data["id"]
        assert data["type"] == "root_ca"

    def test_import_intermediate_ca_endpoint(self, client, ca_data_dir, valid_chain_pems):
        """Test Intermediate CA import API endpoint.

        First imports the Root CA, then imports the Intermediate CA.
        Root CAs must be imported through the root endpoint before importing intermediates.
        """
        root_pem, intermediate_pem = valid_chain_pems

        if ca_data_dir.exists():
            shutil.rmtree(ca_data_dir)
        ca_data_dir.mkdir()

        # Step 1: Import the Root CA first
        root_payload = {
            "ca_cert_content": root_pem,
            "ca_name": "api-imported-root-ca",
        }
        root_response = client.post("/api/cas/import-root", json=root_payload)
        assert root_response.status_code == 201
        root_data = root_response.json()
        root_ca_id = root_data["id"]

        # Step 2: Import the Intermediate CA with reference to the root
        intermediate_payload = {
            "parent_ca_id": root_ca_id,
            "ca_cert_content": intermediate_pem,
            "ca_name": "api-imported-intermediate-ca",
        }

        response = client.post("/api/cas/import-intermediate", json=intermediate_payload)

        assert response.status_code == 201
        data = response.json()
        assert "api-imported-intermediate-ca" in data["id"]
        assert data["type"] == "intermediate_ca"
