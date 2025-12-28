"""Certificate parsing service."""

from pathlib import Path
from typing import Dict, Any, Optional
import logging
from datetime import datetime
import subprocess

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519

logger = logging.getLogger("yacertmanager")


class CertificateParser:
    """Service for parsing X.509 certificates."""

    @staticmethod
    def parse_certificate(cert_path: Path) -> Dict[str, Any]:
        """
        Parse X.509 Certificate from file and extract all relevant data.

        Args:
            cert_path: Path to certificate file

        Returns:
            Dictionary with parsed certificate data

        Raises:
            FileNotFoundError: If certificate file not found
            ValueError: If certificate cannot be parsed
        """
        if not cert_path.exists():
            raise FileNotFoundError(f"Certificate not found: {cert_path}")

        try:
            with open(cert_path, "rb") as f:
                cert_pem = f.read()

            return CertificateParser.parse_certificate_pem(cert_pem.decode('utf-8'))

        except Exception as e:
            logger.error(f"Error parsing certificate {cert_path}: {e}")
            raise ValueError(f"Failed to parse certificate: {e}")

    @staticmethod
    def parse_certificate_pem(cert_pem: str) -> Dict[str, Any]:
        """
        Parse X.509 Certificate from PEM content.

        Args:
            cert_pem: PEM-encoded certificate content

        Returns:
            Dictionary with parsed certificate data

        Raises:
            ValueError: If certificate cannot be parsed
        """
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'), default_backend())

            # Extract key info
            key_info = CertificateParser._extract_key_info(cert.public_key())

            # Extract subject and map to OpenSSL-style keys
            subject_dict = CertificateParser._extract_subject(cert.subject)
            subject_mapped = {
                'CN': subject_dict.get('common_name'),
                'O': subject_dict.get('organization'),
                'OU': subject_dict.get('organizational_unit'),
                'C': subject_dict.get('country'),
                'ST': subject_dict.get('state'),
                'L': subject_dict.get('locality')
            }

            return {
                "subject": subject_mapped,
                "issuer": CertificateParser._extract_subject(cert.issuer),
                "not_before": cert.not_valid_before_utc,
                "not_after": cert.not_valid_after_utc,
                "serial_number": format(cert.serial_number, 'X'),
                "public_key_algorithm": key_info.get('algorithm'),
                "public_key_size": key_info.get('size'),
                "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(':').upper(),
                "sans": CertificateParser._extract_sans(cert),
                "is_ca": CertificateParser._is_ca(cert)
            }

        except Exception as e:
            logger.error(f"Error parsing certificate: {e}")
            raise ValueError(f"Failed to parse certificate: {e}")

    @staticmethod
    def _extract_subject(name: x509.Name) -> Dict[str, Optional[str]]:
        """
        Extract Subject/Issuer DN.

        Args:
            name: X.509 Name object

        Returns:
            Dictionary with subject fields
        """
        def get_attribute(oid):
            try:
                attrs = name.get_attributes_for_oid(oid)
                return attrs[0].value if attrs else None
            except Exception:
                return None

        return {
            "common_name": get_attribute(x509.NameOID.COMMON_NAME),
            "organization": get_attribute(x509.NameOID.ORGANIZATION_NAME),
            "organizational_unit": get_attribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME),
            "country": get_attribute(x509.NameOID.COUNTRY_NAME),
            "state": get_attribute(x509.NameOID.STATE_OR_PROVINCE_NAME),
            "locality": get_attribute(x509.NameOID.LOCALITY_NAME),
        }

    @staticmethod
    def _extract_key_info(public_key) -> Dict[str, Any]:
        """
        Extract public key information.

        Args:
            public_key: Public key object

        Returns:
            Dictionary with key information
        """
        if isinstance(public_key, rsa.RSAPublicKey):
            return {
                "algorithm": "RSA",
                "key_size": public_key.key_size,
                "curve": None
            }
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            curve_name = public_key.curve.name
            # Map OpenSSL names to our standard names
            curve_map = {
                "secp256r1": "P-256",
                "secp384r1": "P-384",
                "secp521r1": "P-521",
            }
            return {
                "algorithm": "ECDSA",
                "key_size": None,
                "curve": curve_map.get(curve_name, curve_name)
            }
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            return {
                "algorithm": "Ed25519",
                "key_size": None,
                "curve": None
            }
        else:
            return {
                "algorithm": "Unknown",
                "key_size": None,
                "curve": None
            }

    @staticmethod
    def _extract_sans(cert: x509.Certificate) -> list[str]:
        """
        Extract Subject Alternative Names.

        Args:
            cert: Certificate object

        Returns:
            List of SANs
        """
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            return [dns.value for dns in san_ext.value]
        except x509.ExtensionNotFound:
            return []

    @staticmethod
    def _is_ca(cert: x509.Certificate) -> bool:
        """
        Check if certificate is a CA.

        Args:
            cert: Certificate object

        Returns:
            True if CA, False otherwise
        """
        try:
            bc = cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.BASIC_CONSTRAINTS
            )
            return bc.value.ca
        except x509.ExtensionNotFound:
            return False

    @staticmethod
    def get_validity_status(not_before: datetime, not_after: datetime) -> tuple[str, str]:
        """
        Get validity status of certificate.

        Args:
            not_before: Certificate start date
            not_after: Certificate end date

        Returns:
            Tuple of (status_class, status_text)
            status_class: Bootstrap class (success, warning, danger)
            status_text: Human-readable status
        """
        now = datetime.now(not_after.tzinfo) if not_after.tzinfo else datetime.now()

        if now < not_before:
            return "warning", "Not yet valid"
        elif now > not_after:
            return "danger", "Expired"
        else:
            # Check if expiring soon (within 30 days)
            days_remaining = (not_after - now).days
            if days_remaining <= 30:
                return "warning", f"Expires in {days_remaining} days"
            else:
                return "success", "Valid"

    @staticmethod
    def certificate_to_text(cert_path: Path) -> str:
        """
        Convert certificate to human-readable text format.

        Args:
            cert_path: Path to certificate file

        Returns:
            Certificate in text format

        Raises:
            ValueError: If conversion fails
        """
        if not cert_path.exists():
            raise ValueError(f"Certificate not found: {cert_path}")

        try:
            # Use OpenSSL to convert to text format
            result = subprocess.run(
                ["openssl", "x509", "-in", str(cert_path), "-text", "-noout"],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout

        except subprocess.CalledProcessError as e:
            logger.error(f"Error converting certificate to text: {e.stderr}")
            raise ValueError(f"Failed to convert certificate to text: {e.stderr}")
        except FileNotFoundError:
            raise ValueError("OpenSSL not found in PATH")

    @staticmethod
    def verify_key_pair(cert_path: Path, key_path: Path) -> bool:
        """
        Verify that certificate and private key match.

        Args:
            cert_path: Path to certificate
            key_path: Path to private key

        Returns:
            True if key pair matches, False otherwise
        """
        try:
            # Load certificate
            with open(cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read(), default_backend())

            # Load private key
            from cryptography.hazmat.primitives import serialization
            with open(key_path, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )

            # Get public key from private key
            public_key_from_private = private_key.public_key()
            public_key_from_cert = cert.public_key()

            # Compare public key bytes
            from cryptography.hazmat.primitives import serialization as ser
            pub_from_private_bytes = public_key_from_private.public_bytes(
                encoding=ser.Encoding.PEM,
                format=ser.PublicFormat.SubjectPublicKeyInfo
            )
            pub_from_cert_bytes = public_key_from_cert.public_bytes(
                encoding=ser.Encoding.PEM,
                format=ser.PublicFormat.SubjectPublicKeyInfo
            )

            return pub_from_private_bytes == pub_from_cert_bytes

        except Exception as e:
            logger.error(f"Error verifying key pair: {e}")
            return False
