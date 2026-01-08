"""Pytest configuration and shared fixtures."""

import shutil
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.models.auth import Session
from app.models.ca import CAConfig, CACreateRequest, CAType, KeyAlgorithm, KeyConfig, Subject
from app.models.certificate import CertCreateRequest
from app.models.config import AuthSettings
from app.services.auth_service import AuthService
from app.services.ca_service import CAService
from app.services.cert_service import CertificateService
from app.services.csr_service import CSRService
from app.services.openssl_service import OpenSSLService


@pytest.fixture(scope="session")
def test_data_dir():
    """Create a temporary directory for test data."""
    temp_dir = tempfile.mkdtemp(prefix="homelabpki_test_")
    yield Path(temp_dir)
    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def ca_data_dir(test_data_dir):
    """Create a fresh CA data directory for each test."""
    ca_dir = test_data_dir / f"ca_data_{datetime.now().timestamp()}"
    ca_dir.mkdir(parents=True, exist_ok=True)
    yield ca_dir
    # Cleanup after test
    if ca_dir.exists():
        shutil.rmtree(ca_dir, ignore_errors=True)


@pytest.fixture
def openssl_service():
    """Create OpenSSL service instance."""
    return OpenSSLService()


@pytest.fixture
def ca_service(ca_data_dir, openssl_service):
    """Create CA service instance with test directory."""
    return CAService(ca_data_dir, openssl_service)


@pytest.fixture
def cert_service(ca_data_dir, openssl_service, ca_service):
    """Create Certificate service instance with test directory."""
    return CertificateService(ca_data_dir, openssl_service, ca_service)


@pytest.fixture
def csr_service(ca_data_dir, openssl_service):
    """Create CSR service instance with test directory."""
    return CSRService(ca_data_dir, openssl_service)


@pytest.fixture
def sample_ca_subject():
    """Create a sample CA subject."""
    return Subject(
        common_name="Test Root CA",
        organization="Test Organization",
        organizational_unit="Test Unit",
        country="US",
        state="California",
        locality="San Francisco",
    )


@pytest.fixture
def sample_key_config():
    """Create a sample key configuration (RSA 2048) - passwords no longer stored."""
    return KeyConfig(algorithm="RSA", key_size=2048, encrypted=True)


@pytest.fixture
def sample_root_ca_request(sample_ca_subject):
    """Create a sample Root CA creation request."""
    return CACreateRequest(
        type=CAType.ROOT_CA,
        subject=sample_ca_subject,
        key_algorithm=KeyAlgorithm.RSA,
        key_size=2048,
        key_password="test_password_123",
        validity_days=365,
    )


@pytest.fixture
def sample_cert_subject():
    """Create a sample certificate subject."""
    return Subject(common_name="test.example.com", organization="Test Organization", country="US")


@pytest.fixture
def sample_cert_request(sample_cert_subject):
    """Create a sample certificate creation request with passwords."""
    return CertCreateRequest(
        subject=sample_cert_subject,
        sans=["test.example.com", "*.test.example.com", "192.168.1.100"],
        key_algorithm=KeyAlgorithm.RSA,
        key_size=2048,
        key_password="test_password_123",  # Password for key encryption (not stored)
        validity_days=365,
        issuing_ca_id="root-ca-test-root-ca",
        issuing_ca_password="test_password_123",  # Password for the issuing CA
    )


@pytest.fixture
def auth_service(ca_data_dir):
    """Create auth service instance with auth enabled for testing."""
    auth_settings = AuthSettings(enabled=True, session_expiry_hours=24)
    service = AuthService(auth_settings, config_path=ca_data_dir / "test_config.yaml")
    return service


@pytest.fixture
def auth_token(auth_service):
    """Get a valid auth token for testing."""
    session = auth_service.create_session()
    return session.token


@pytest.fixture
def auth_headers(auth_token):
    """Get auth headers for API requests."""
    return {"Authorization": f"Bearer {auth_token}"}


@pytest.fixture
def client(ca_data_dir, openssl_service):
    """Create FastAPI test client with isolated test directory and auth disabled."""
    from app.api.dependencies import (
        get_auth_service,
        get_ca_data_dir,
        get_ca_service,
        get_cert_service,
        reset_auth_service,
    )
    from app.services.ca_service import CAService
    from app.services.cert_service import CertificateService
    from main import app

    # Reset auth service singleton before tests
    reset_auth_service()

    # Create auth service with auth DISABLED for regular tests
    disabled_auth_settings = AuthSettings(enabled=False)
    disabled_auth_service = AuthService(disabled_auth_settings, config_path=ca_data_dir / "test_config.yaml")

    # Override dependencies to use test directory
    def override_ca_data_dir():
        return ca_data_dir

    def override_ca_service():
        return CAService(ca_data_dir, openssl_service)

    def override_cert_service():
        return CertificateService(ca_data_dir, openssl_service, override_ca_service())

    def override_auth_service():
        return disabled_auth_service

    app.dependency_overrides[get_ca_data_dir] = override_ca_data_dir
    app.dependency_overrides[get_ca_service] = override_ca_service
    app.dependency_overrides[get_cert_service] = override_cert_service
    app.dependency_overrides[get_auth_service] = override_auth_service

    client = TestClient(app)
    yield client

    # Clean up
    app.dependency_overrides.clear()
    reset_auth_service()


@pytest.fixture
def client_with_auth(ca_data_dir, openssl_service, auth_service, auth_token):
    """Create FastAPI test client with authentication enabled."""
    from app.api.dependencies import (
        get_auth_service,
        get_ca_data_dir,
        get_ca_service,
        get_cert_service,
        reset_auth_service,
    )
    from app.services.ca_service import CAService
    from app.services.cert_service import CertificateService
    from main import app

    # Reset auth service singleton before tests
    reset_auth_service()

    # Override dependencies to use test directory
    def override_ca_data_dir():
        return ca_data_dir

    def override_ca_service():
        return CAService(ca_data_dir, openssl_service)

    def override_cert_service():
        return CertificateService(ca_data_dir, openssl_service, override_ca_service())

    def override_auth_service():
        return auth_service

    app.dependency_overrides[get_ca_data_dir] = override_ca_data_dir
    app.dependency_overrides[get_ca_service] = override_ca_service
    app.dependency_overrides[get_cert_service] = override_cert_service
    app.dependency_overrides[get_auth_service] = override_auth_service

    client = TestClient(app)
    yield client

    # Clean up
    app.dependency_overrides.clear()
    reset_auth_service()


@pytest.fixture
def created_root_ca(ca_service, sample_root_ca_request):
    """Create a test Root CA and return its response."""
    return ca_service.create_root_ca(sample_root_ca_request)


@pytest.fixture
def created_intermediate_ca(ca_service, created_root_ca):
    """Create a test Intermediate CA under the root CA."""
    request = CACreateRequest(
        type=CAType.INTERMEDIATE_CA,
        subject=Subject(common_name="Test Intermediate CA", organization="Test Organization", country="US"),
        key_algorithm=KeyAlgorithm.RSA,
        key_size=2048,
        key_password="intermediate_password_123",  # Password for key encryption (not stored)
        validity_days=365,
        parent_ca_password="test_password_123",  # Password for root CA
    )
    return ca_service.create_intermediate_ca(request, created_root_ca.id)
