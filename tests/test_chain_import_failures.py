import shutil
from datetime import datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.models.ca import IntermediateCAImportRequest, RootCAImportRequest
from app.services.ca_service import CAService


# --- Helper Functions (duplicated for test coherence) ---
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


def test_import_intermediate_fails_without_parent_ca_id(ca_service: CAService):
    """Test that importing an intermediate CA without parent_ca_id fails."""
    root_key = generate_key()
    int_key = generate_key()

    int_cert = generate_cert("Orphan Intermediate", "Unknown Root", root_key, int_key.public_key(), ca=True)
    intermediate_pem = to_pem(int_cert)

    if ca_service.ca_data_dir.exists():
        shutil.rmtree(ca_service.ca_data_dir)
    ca_service.ca_data_dir.mkdir()

    # Try to import without specifying parent_ca_id
    req = IntermediateCAImportRequest(parent_ca_id="", ca_cert_content=intermediate_pem, ca_name="orphan-ca")

    with pytest.raises(ValueError, match="Parent CA ID is required"):
        ca_service.import_intermediate_ca(req)


def test_import_intermediate_fails_with_nonexistent_parent(ca_service: CAService):
    """Test that importing an intermediate CA with nonexistent parent fails."""
    root_key = generate_key()
    int_key = generate_key()

    int_cert = generate_cert("Orphan Intermediate", "Unknown Root", root_key, int_key.public_key(), ca=True)
    intermediate_pem = to_pem(int_cert)

    if ca_service.ca_data_dir.exists():
        shutil.rmtree(ca_service.ca_data_dir)
    ca_service.ca_data_dir.mkdir()

    # Try to import with a parent_ca_id that doesn't exist
    req = IntermediateCAImportRequest(
        parent_ca_id="nonexistent-parent-ca", ca_cert_content=intermediate_pem, ca_name="orphan-ca"
    )

    with pytest.raises(ValueError, match="Parent CA not found"):
        ca_service.import_intermediate_ca(req)


def test_import_fails_with_multiple_certificates(ca_service: CAService):
    """Test that importing multiple certificates in one file fails."""
    root_key = generate_key()
    root_cert = generate_cert("Root One", "Root One", root_key, root_key.public_key(), ca=True)

    root_key2 = generate_key()
    root_cert2 = generate_cert("Root Two", "Root Two", root_key2, root_key2.public_key(), ca=True)

    # Bundle two certificates together
    bundle_pem = to_pem(root_cert) + to_pem(root_cert2)

    if ca_service.ca_data_dir.exists():
        shutil.rmtree(ca_service.ca_data_dir)
    ca_service.ca_data_dir.mkdir()

    req = RootCAImportRequest(ca_cert_content=bundle_pem, ca_name="bundle-root")

    with pytest.raises(ValueError, match="Multiple certificates are not supported"):
        ca_service.import_root_ca(req)
