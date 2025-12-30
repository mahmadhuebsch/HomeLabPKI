"""Tests for certificate chain import functionality."""

import shutil
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.models.ca import CACreateRequest, CAType, IntermediateCAImportRequest, KeyConfig, RootCAImportRequest, Subject
from app.models.certificate import CertImportRequest
from app.services.ca_service import CAService
from app.services.cert_service import CertificateService
from app.utils.file_utils import FileUtils


# --- Helper Functions for Data Generation ---
def generate_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def generate_cert(subject_name, issuer_name, issuer_key, public_key, ca=False, serial=None):
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)]))
    builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)]))

    today = datetime.utcnow()
    builder = builder.not_valid_before(today)
    builder = builder.not_valid_after(today + timedelta(days=30))

    builder = builder.serial_number(serial if serial else x509.random_serial_number())
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
def valid_chain_data():
    """Generates a valid chain: Root -> Intermediate -> Leaf."""
    root_key = generate_key()
    root_cert = generate_cert("Valid Root", "Valid Root", root_key, root_key.public_key(), ca=True)

    int_key = generate_key()
    int_cert = generate_cert("Valid Intermediate", "Valid Root", root_key, int_key.public_key(), ca=True)

    leaf_key = generate_key()
    leaf_cert = generate_cert("Valid Leaf", "Valid Intermediate", int_key, leaf_key.public_key(), ca=False)

    return {
        "root_pem": to_pem(root_cert),
        "intermediate_pem": to_pem(int_cert),
        "leaf_pem": to_pem(leaf_cert),
        "full_chain_pem": to_pem(leaf_cert) + to_pem(int_cert) + to_pem(root_cert),
        "chain_no_root_pem": to_pem(leaf_cert) + to_pem(int_cert),
    }


def test_import_ca_chain_full(ca_service: CAService, valid_chain_data):
    """Test importing a full CA chain (Root first, then Intermediate).

    Root CAs must be imported through the root endpoint before importing intermediates.
    """
    root_pem = valid_chain_data["root_pem"]
    intermediate_pem = valid_chain_data["intermediate_pem"]

    # Clear existing CAs to simulate a fresh import
    if ca_service.ca_data_dir.exists():
        shutil.rmtree(ca_service.ca_data_dir)
    ca_service.ca_data_dir.mkdir()

    # Step 1: Import the Root CA first
    root_import_request = RootCAImportRequest(
        ca_cert_content=root_pem,
        ca_name="valid-root",
    )
    root_result = ca_service.import_root_ca(root_import_request)
    assert root_result is not None
    root_ca_id = root_result.id

    # Step 2: Import the Intermediate CA with reference to the root
    import_request = IntermediateCAImportRequest(
        parent_ca_id=root_ca_id,
        ca_cert_content=intermediate_pem,
        ca_name="imported-intermediate",
    )

    result = ca_service.import_intermediate_ca(import_request)

    assert result is not None
    assert "imported-intermediate" in result.id
    assert "root-ca-valid-root" in result.id  # Check if parent was referenced correctly

    # Verify directories were created
    imported_root_dir = ca_service.ca_data_dir / "root-ca-valid-root"
    imported_intermediate_dir = imported_root_dir / "intermediate-ca-imported-intermediate"

    assert imported_root_dir.exists()
    assert imported_intermediate_dir.exists()
    assert (imported_intermediate_dir / "ca.crt").exists()


def test_import_ca_existing_root(ca_service: CAService, valid_chain_data):
    """Test importing an intermediate CA when the root CA already exists."""
    root_pem = valid_chain_data["root_pem"]
    intermediate_pem = valid_chain_data["intermediate_pem"]

    # 1. First import the root individually
    shutil.rmtree(ca_service.ca_data_dir)
    ca_service.ca_data_dir.mkdir()

    root_import_req = RootCAImportRequest(ca_cert_content=root_pem, ca_name="valid-root")
    ca_service.import_root_ca(root_import_req)

    root_ca_id = "root-ca-valid-root"
    assert (ca_service.ca_data_dir / root_ca_id).exists()

    # 2. Now import the intermediate referencing the existing root
    import_request = IntermediateCAImportRequest(
        parent_ca_id=root_ca_id, ca_cert_content=intermediate_pem, ca_name="imported-intermediate-2"
    )

    result = ca_service.import_intermediate_ca(import_request)
    assert result is not None
    assert result.id == f"{root_ca_id}/intermediate-ca-imported-intermediate-2"


def test_import_cert_with_full_chain(cert_service: CertificateService, ca_service: CAService, valid_chain_data):
    """Test importing a leaf certificate with its full chain.

    Root CAs and Intermediate CAs must be imported through their respective endpoints
    before importing certificates.
    """
    root_pem = valid_chain_data["root_pem"]
    intermediate_pem = valid_chain_data["intermediate_pem"]
    leaf_pem = valid_chain_data["leaf_pem"]

    # Clear existing data to simulate fresh import
    if ca_service.ca_data_dir.exists():
        shutil.rmtree(ca_service.ca_data_dir)
    ca_service.ca_data_dir.mkdir()

    # Step 1: Import the Root CA first
    root_import_request = RootCAImportRequest(
        ca_cert_content=root_pem,
        ca_name="valid-root",
    )
    root_result = ca_service.import_root_ca(root_import_request)
    root_ca_id = root_result.id

    # Step 2: Import the Intermediate CA
    int_import_request = IntermediateCAImportRequest(
        parent_ca_id=root_ca_id,
        ca_cert_content=intermediate_pem,
        ca_name="valid-intermediate",
    )
    int_result = ca_service.import_intermediate_ca(int_import_request)
    int_ca_id = int_result.id

    # Step 3: Import the leaf certificate
    import_request = CertImportRequest(
        issuing_ca_id=int_ca_id,
        cert_content=leaf_pem,
        cert_name="imported-leaf",
    )

    result = cert_service.import_certificate(import_request)

    assert result is not None
    assert result.id.endswith("/certs/imported-leaf")

    # Check that the intermediate and root exist
    root_id = "root-ca-valid-root"
    int_id = "intermediate-ca-valid-intermediate"

    assert (ca_service.ca_data_dir / root_id).exists()
    assert (ca_service.ca_data_dir / root_id / int_id).exists()

    # Check that the final cert exists in the right place
    final_cert_path = ca_service.ca_data_dir / result.id
    assert final_cert_path.exists()
    assert (final_cert_path / "fullchain.pem").exists()


def test_import_single_root_ca(ca_service: CAService, valid_chain_data):
    """Test importing a single root CA certificate."""
    root_pem = valid_chain_data["root_pem"]

    if ca_service.ca_data_dir.exists():
        shutil.rmtree(ca_service.ca_data_dir)
    ca_service.ca_data_dir.mkdir()

    import_request = RootCAImportRequest(ca_cert_content=root_pem, ca_name="new-imported-root")
    result = ca_service.import_root_ca(import_request)
    assert result is not None
    assert result.id == "root-ca-new-imported-root"


def test_import_root_fails_if_not_self_signed(ca_service: CAService, valid_chain_data):
    """Test that Root CA import fails if the certificate is not self-signed."""
    # Use intermediate cert which is NOT self-signed
    intermediate_pem = valid_chain_data["intermediate_pem"]

    import_request = RootCAImportRequest(ca_cert_content=intermediate_pem, ca_name="not-a-root")
    with pytest.raises(ValueError, match="not a self-signed Root CA"):
        ca_service.import_root_ca(import_request)


# --- Tests for Chain Import (Full Chain) ---
@pytest.fixture
def chain_only_cas():
    """Generates a CA-only chain: Root -> Intermediate (no leaf)."""
    root_key = generate_key()
    root_cert = generate_cert("Chain Root CA", "Chain Root CA", root_key, root_key.public_key(), ca=True)

    int_key = generate_key()
    int_cert = generate_cert("Chain Intermediate CA", "Chain Root CA", root_key, int_key.public_key(), ca=True)

    return {
        "root_pem": to_pem(root_cert),
        "int_pem": to_pem(int_cert),
        "chain_pem": to_pem(root_cert) + to_pem(int_cert),
        "chain_reversed_pem": to_pem(int_cert) + to_pem(root_cert),
    }


@pytest.fixture
def three_level_chain():
    """Generates a three-level CA chain: Root -> Int1 -> Int2."""
    root_key = generate_key()
    root_cert = generate_cert("Three Level Root", "Three Level Root", root_key, root_key.public_key(), ca=True)

    int1_key = generate_key()
    int1_cert = generate_cert("Intermediate Level 1", "Three Level Root", root_key, int1_key.public_key(), ca=True)

    int2_key = generate_key()
    int2_cert = generate_cert("Intermediate Level 2", "Intermediate Level 1", int1_key, int2_key.public_key(), ca=True)

    return {
        "root_pem": to_pem(root_cert),
        "int1_pem": to_pem(int1_cert),
        "int2_pem": to_pem(int2_cert),
        "chain_pem": to_pem(root_cert) + to_pem(int1_cert) + to_pem(int2_cert),
        "chain_shuffled_pem": to_pem(int2_cert) + to_pem(root_cert) + to_pem(int1_cert),
    }


def test_import_chain_two_levels(ca_service: CAService, chain_only_cas):
    """Test importing a complete two-level chain (root + intermediate)."""
    from app.models.ca import ChainImportRequest

    if ca_service.ca_data_dir.exists():
        shutil.rmtree(ca_service.ca_data_dir)
    ca_service.ca_data_dir.mkdir()

    request = ChainImportRequest(chain_content=chain_only_cas["chain_pem"])
    result = ca_service.import_certificate_chain(request)

    assert result is not None
    assert len(result.imported_cas) == 2
    assert len(result.imported_certs) == 0
    assert "imported 2 ca(s)" in result.message.lower()

    # Verify root CA was imported
    root_dir = ca_service.ca_data_dir / "root-ca-chain-root-ca"
    assert root_dir.exists()
    assert (root_dir / "ca.crt").exists()

    # Verify intermediate CA was imported under root
    int_dir = root_dir / "intermediate-ca-chain-intermediate-ca"
    assert int_dir.exists()
    assert (int_dir / "ca.crt").exists()


def test_import_chain_reversed_order(ca_service: CAService, chain_only_cas):
    """Test that chain import works even when certificates are in reverse order."""
    from app.models.ca import ChainImportRequest

    if ca_service.ca_data_dir.exists():
        shutil.rmtree(ca_service.ca_data_dir)
    ca_service.ca_data_dir.mkdir()

    # Use reversed order (intermediate first, then root)
    request = ChainImportRequest(chain_content=chain_only_cas["chain_reversed_pem"])
    result = ca_service.import_certificate_chain(request)

    assert result is not None
    assert len(result.imported_cas) == 2

    # Verify correct nesting
    root_dir = ca_service.ca_data_dir / "root-ca-chain-root-ca"
    int_dir = root_dir / "intermediate-ca-chain-intermediate-ca"
    assert root_dir.exists()
    assert int_dir.exists()


def test_import_chain_three_levels(ca_service: CAService, three_level_chain):
    """Test importing a three-level CA chain."""
    from app.models.ca import ChainImportRequest

    if ca_service.ca_data_dir.exists():
        shutil.rmtree(ca_service.ca_data_dir)
    ca_service.ca_data_dir.mkdir()

    request = ChainImportRequest(chain_content=three_level_chain["chain_pem"])
    result = ca_service.import_certificate_chain(request)

    assert result is not None
    assert len(result.imported_cas) == 3

    # Verify correct nesting
    root_dir = ca_service.ca_data_dir / "root-ca-three-level-root"
    int1_dir = root_dir / "intermediate-ca-intermediate-level-1"
    int2_dir = int1_dir / "intermediate-ca-intermediate-level-2"

    assert root_dir.exists()
    assert int1_dir.exists()
    assert int2_dir.exists()


def test_import_chain_shuffled_order(ca_service: CAService, three_level_chain):
    """Test that chain import works with shuffled certificate order."""
    from app.models.ca import ChainImportRequest

    if ca_service.ca_data_dir.exists():
        shutil.rmtree(ca_service.ca_data_dir)
    ca_service.ca_data_dir.mkdir()

    request = ChainImportRequest(chain_content=three_level_chain["chain_shuffled_pem"])
    result = ca_service.import_certificate_chain(request)

    assert result is not None
    assert len(result.imported_cas) == 3


def test_import_chain_with_leaf_imported(ca_service: CAService, cert_service: CertificateService, valid_chain_data):
    """Test that leaf certificates are imported along with CAs."""
    from app.models.ca import ChainImportRequest

    if ca_service.ca_data_dir.exists():
        shutil.rmtree(ca_service.ca_data_dir)
    ca_service.ca_data_dir.mkdir()

    # full_chain_pem includes leaf + intermediate + root
    request = ChainImportRequest(chain_content=valid_chain_data["full_chain_pem"])
    result = ca_service.import_certificate_chain(request, cert_service)

    assert result is not None
    assert len(result.imported_cas) == 2  # Root + intermediate
    assert len(result.imported_certs) == 1  # Leaf certificate

    # Verify certificate was imported under the intermediate CA
    int_ca_dir = ca_service.ca_data_dir / "root-ca-valid-root" / "intermediate-ca-valid-intermediate"
    certs_dir = int_ca_dir / "certs"
    assert certs_dir.exists()
    # Should have a certificate directory
    cert_dirs = list(certs_dir.iterdir())
    assert len(cert_dirs) == 1


def test_import_chain_single_cert_fails(ca_service: CAService, valid_chain_data):
    """Test that importing a single certificate as chain fails."""
    from app.models.ca import ChainImportRequest

    request = ChainImportRequest(chain_content=valid_chain_data["root_pem"])

    with pytest.raises(ValueError, match="at least 2 certificates"):
        ca_service.import_certificate_chain(request)


def test_import_chain_existing_root_reused(ca_service: CAService, chain_only_cas):
    """Test that existing root CA is reused during chain import."""
    from app.models.ca import ChainImportRequest

    if ca_service.ca_data_dir.exists():
        shutil.rmtree(ca_service.ca_data_dir)
    ca_service.ca_data_dir.mkdir()

    # First, import just the root
    root_request = RootCAImportRequest(ca_cert_content=chain_only_cas["root_pem"], ca_name="chain-root-ca")
    ca_service.import_root_ca(root_request)

    # Now import the full chain - root should be recognized
    chain_request = ChainImportRequest(chain_content=chain_only_cas["chain_pem"])
    result = ca_service.import_certificate_chain(chain_request)

    assert result is not None
    # Only intermediate should be imported (root already exists)
    assert len(result.imported_cas) == 1
    assert result.imported_cas[0].type.value == "intermediate_ca"
