"""Tests for Parser service."""

import pytest
from datetime import datetime, timedelta

from app.services.parser_service import CertificateParser


@pytest.mark.unit
@pytest.mark.requires_openssl
class TestCertificateParser:
    """Test certificate parser functionality."""

    def test_parse_certificate(self, created_root_ca):
        """Test parsing a certificate."""
        from pathlib import Path

        cert_path = Path(created_root_ca.path) / "ca.crt"

        cert_info = CertificateParser.parse_certificate(cert_path)

        assert "subject" in cert_info
        assert "issuer" in cert_info
        assert "not_before" in cert_info
        assert "not_after" in cert_info
        assert "serial_number" in cert_info
        assert "fingerprint_sha256" in cert_info
        assert cert_info["is_ca"] is True

    def test_parse_nonexistent_certificate_fails(self):
        """Test parsing nonexistent certificate fails."""
        from pathlib import Path

        nonexistent_path = Path("/nonexistent/cert.crt")

        with pytest.raises(FileNotFoundError):
            CertificateParser.parse_certificate(nonexistent_path)

    def test_certificate_to_text(self, created_root_ca):
        """Test converting certificate to text format."""
        from pathlib import Path

        cert_path = Path(created_root_ca.path) / "ca.crt"

        text = CertificateParser.certificate_to_text(cert_path)

        assert text is not None
        assert "Certificate:" in text
        assert "Subject:" in text
        assert "Issuer:" in text
        assert "Validity" in text

    def test_get_validity_status_valid(self):
        """Test validity status for valid certificate."""
        now = datetime.now()
        not_before = now - timedelta(days=1)
        not_after = now + timedelta(days=100)

        status_class, status_text = CertificateParser.get_validity_status(not_before, not_after)

        assert status_class == "success"
        assert "Valid" in status_text

    def test_get_validity_status_expiring_soon(self):
        """Test validity status for expiring certificate."""
        now = datetime.now()
        not_before = now - timedelta(days=1)
        not_after = now + timedelta(days=15)  # Expires in 15 days

        status_class, status_text = CertificateParser.get_validity_status(not_before, not_after)

        assert status_class == "warning"
        assert "days" in status_text

    def test_get_validity_status_expired(self):
        """Test validity status for expired certificate."""
        now = datetime.now()
        not_before = now - timedelta(days=100)
        not_after = now - timedelta(days=1)  # Expired

        status_class, status_text = CertificateParser.get_validity_status(not_before, not_after)

        assert status_class == "danger"
        assert "Expired" in status_text

    def test_get_validity_status_not_yet_valid(self):
        """Test validity status for not yet valid certificate."""
        now = datetime.now()
        not_before = now + timedelta(days=1)  # Future
        not_after = now + timedelta(days=100)

        status_class, status_text = CertificateParser.get_validity_status(not_before, not_after)

        assert status_class == "warning"
        assert "Not yet valid" in status_text
