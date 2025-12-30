import pytest
import shutil
from pathlib import Path
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.models.ca import IntermediateCAImportRequest, RootCAImportRequest
from app.models.certificate import CertImportRequest
from app.services.ca_service import CAService
from app.services.cert_service import CertificateService


# --- Helper Functions ---
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
def clean_ca_service(ca_service):
    if ca_service.ca_data_dir.exists():
        shutil.rmtree(ca_service.ca_data_dir)
    ca_service.ca_data_dir.mkdir()
    return ca_service


@pytest.fixture
def created_root_ca(ca_service, clean_ca_service):
    # Create a real root CA for testing
    from app.models.ca import CACreateRequest, KeyConfig, Subject, CAType

    req = CACreateRequest(
        type=CAType.ROOT_CA,
        subject=Subject(common_name="Existing Root"),
        key_config=KeyConfig(algorithm="RSA", key_size=2048, password="password"),
        validity_days=30,
    )
    return ca_service.create_root_ca(req)


def test_import_server_cert_as_root_fails(clean_ca_service):
    """Test that importing a non-CA cert as Root CA fails."""
    key = generate_key()
    # Leaf cert (CA=False)
    cert = generate_cert("Not A CA", "Not A CA", key, key.public_key(), ca=False)
    pem = to_pem(cert)

    req = RootCAImportRequest(ca_name="bad-root", ca_cert_content=pem)

    with pytest.raises(ValueError, match="not a CA certificate"):
        clean_ca_service.import_root_ca(req)


def test_import_server_cert_as_intermediate_fails(clean_ca_service, created_root_ca):
    """Test that importing a non-CA cert as Intermediate CA fails."""
    key = generate_key()
    # Leaf cert (CA=False)
    cert = generate_cert("Not A CA Int", "Existing Root", key, key.public_key(), ca=False)
    pem = to_pem(cert)

    req = IntermediateCAImportRequest(ca_name="bad-int", ca_cert_content=pem, parent_ca_id=created_root_ca.id)

    with pytest.raises(ValueError, match="not a CA certificate"):
        clean_ca_service.import_intermediate_ca(req)


def test_import_root_as_intermediate_fails(clean_ca_service, created_root_ca):
    """Test that importing a self-signed Root CA as Intermediate CA fails."""
    key = generate_key()
    # Root cert (CA=True, Self-Signed)
    cert = generate_cert("Root As Int", "Root As Int", key, key.public_key(), ca=True)
    pem = to_pem(cert)

    req = IntermediateCAImportRequest(ca_name="root-as-int", ca_cert_content=pem, parent_ca_id=created_root_ca.id)

    with pytest.raises(ValueError, match="self-signed Root CA.*Import Root CA"):
        clean_ca_service.import_intermediate_ca(req)


def test_import_ca_as_server_cert_fails(cert_service, created_root_ca):
    """Test that importing a CA certificate as a Server Certificate fails."""
    key = generate_key()
    # CA cert (CA=True)
    cert = generate_cert("CA As Leaf", "Existing Root", key, key.public_key(), ca=True)
    pem = to_pem(cert)

    req = CertImportRequest(cert_name="ca-as-leaf", cert_content=pem, issuing_ca_id=created_root_ca.id)

    with pytest.raises(ValueError, match="CA certificates must be imported via the CA Import feature"):
        cert_service.import_certificate(req)
