"""CRL management service."""

import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

from app.models.certificate import ServerCertConfig
from app.models.crl import (
    REVOCATION_REASON_CODES,
    CRLConfig,
    CRLResponse,
    RevocationEntry,
    RevocationReason,
)
from app.services.openssl_service import OpenSSLService
from app.services.yaml_service import YAMLService
from app.utils.file_utils import FileUtils

logger = logging.getLogger("homelabpki")


class CRLService:
    """Service for CRL management operations."""

    def __init__(self, ca_data_dir: Path, openssl_service: OpenSSLService):
        self.ca_data_dir = ca_data_dir
        self.openssl_service = openssl_service

    def initialize_crl_files(self, ca_dir: Path) -> None:
        """Initialize CRL-related files for a CA if they don't exist."""
        # Create index.txt (empty file for OpenSSL database)
        index_file = ca_dir / "index.txt"
        if not index_file.exists():
            FileUtils.write_file(index_file, "")

        # Create index.txt.attr
        attr_file = ca_dir / "index.txt.attr"
        if not attr_file.exists():
            FileUtils.write_file(attr_file, "unique_subject = no\n")

        # Create crlnumber
        crlnumber_file = ca_dir / "crlnumber"
        if not crlnumber_file.exists():
            FileUtils.write_file(crlnumber_file, "01\n")

        # Create crl directory
        crl_dir = ca_dir / "crl"
        FileUtils.ensure_directory(crl_dir)

        # Create CRL config if not exists
        crl_config_path = crl_dir / "config.yaml"
        if not crl_config_path.exists():
            ca_id = str(ca_dir.relative_to(self.ca_data_dir))
            crl_config = CRLConfig(ca_id=ca_id)
            YAMLService.save_config_yaml(crl_config_path, crl_config.model_dump())

        # Regenerate openssl.cnf if it doesn't have CRL support
        # (for CAs created before CRL feature was added)
        openssl_cnf = ca_dir / "openssl.cnf"
        if openssl_cnf.exists():
            content = FileUtils.read_file(openssl_cnf)
            # Check if [ca] section exists
            if "[ca]" not in content:
                logger.info(f"Updating openssl.cnf with CRL support for {ca_dir.name}")
                # Determine if this is a root or intermediate CA
                ca_config_path = ca_dir / "config.yaml"
                if ca_config_path.exists():
                    ca_config_data = YAMLService.load_config_yaml(ca_config_path)
                    ca_type = ca_config_data.get("type", "root_ca")
                    config_type = "root_ca" if ca_type == "root_ca" else "intermediate_ca"
                    self.openssl_service.generate_openssl_config(config_type, openssl_cnf)
                else:
                    # Default to root_ca if no config found
                    self.openssl_service.generate_openssl_config("root_ca", openssl_cnf)

    def revoke_certificate(
        self,
        cert_id: str,
        ca_password: str,
        reason: RevocationReason = RevocationReason.UNSPECIFIED,
    ) -> CRLResponse:
        """
        Revoke a certificate and regenerate the CRL.

        Args:
            cert_id: Certificate ID (e.g., "root-ca-xxx/certs/cert-name")
            ca_password: Password for the issuing CA's private key
            reason: Revocation reason

        Returns:
            Updated CRL response

        Raises:
            ValueError: If certificate not found or already revoked
        """
        # Parse cert_id to get CA directory and cert directory
        cert_dir = self.ca_data_dir / cert_id
        if not cert_dir.exists():
            raise ValueError(f"Certificate not found: {cert_id}")

        # Get issuing CA directory (cert is in ca_dir/certs/cert_name)
        ca_dir = cert_dir.parent.parent

        # Verify CA password
        ca_key_path = ca_dir / "ca.key"
        if not self.openssl_service.verify_key_password(ca_key_path, ca_password):
            raise ValueError("Invalid CA password")

        # Load certificate config
        cert_config_path = cert_dir / "config.yaml"
        cert_config_data = YAMLService.load_config_yaml(cert_config_path)
        cert_config = ServerCertConfig(**cert_config_data)

        # Check if already revoked
        if cert_config_data.get("revoked_at"):
            raise ValueError("Certificate is already revoked")

        # Initialize CRL files if needed
        self.initialize_crl_files(ca_dir)

        # Update OpenSSL index.txt with revocation entry
        self._add_to_index(ca_dir, cert_config, reason)

        # Update certificate config with revocation info
        cert_config_data["revoked_at"] = datetime.now().isoformat()
        cert_config_data["revocation_reason"] = reason.value
        YAMLService.save_config_yaml(cert_config_path, cert_config_data)

        # Update CRL config
        ca_id = str(ca_dir.relative_to(self.ca_data_dir))
        crl_config = self._load_crl_config(ca_dir)
        entry = RevocationEntry(
            serial_number=cert_config.serial_number,
            reason=reason,
            cert_id=cert_id,
            common_name=cert_config.subject.common_name,
        )
        crl_config.entries.append(entry)
        self._save_crl_config(ca_dir, crl_config)

        # Regenerate CRL (auto-regeneration)
        return self.generate_crl(ca_id, ca_password)

    def unrevoke_certificate(self, cert_id: str, ca_password: str) -> CRLResponse:
        """
        Remove a certificate from CRL (only for certificateHold reason).

        Args:
            cert_id: Certificate ID
            ca_password: CA password

        Returns:
            Updated CRL response

        Raises:
            ValueError: If certificate not revoked or not certificateHold
        """
        cert_dir = self.ca_data_dir / cert_id
        if not cert_dir.exists():
            raise ValueError(f"Certificate not found: {cert_id}")

        ca_dir = cert_dir.parent.parent

        # Verify CA password
        ca_key_path = ca_dir / "ca.key"
        if not self.openssl_service.verify_key_password(ca_key_path, ca_password):
            raise ValueError("Invalid CA password")

        # Load certificate config
        cert_config_path = cert_dir / "config.yaml"
        cert_config_data = YAMLService.load_config_yaml(cert_config_path)

        if not cert_config_data.get("revoked_at"):
            raise ValueError("Certificate is not revoked")

        if cert_config_data.get("revocation_reason") != "certificateHold":
            raise ValueError("Only certificates with 'certificateHold' reason can be unrevoked")

        # Remove from index.txt
        self._remove_from_index(ca_dir, cert_config_data.get("serial_number"))

        # Update certificate config
        cert_config_data.pop("revoked_at", None)
        cert_config_data.pop("revocation_reason", None)
        YAMLService.save_config_yaml(cert_config_path, cert_config_data)

        # Update CRL config
        crl_config = self._load_crl_config(ca_dir)
        crl_config.entries = [e for e in crl_config.entries if e.cert_id != cert_id]
        self._save_crl_config(ca_dir, crl_config)

        # Regenerate CRL
        ca_id = str(ca_dir.relative_to(self.ca_data_dir))
        return self.generate_crl(ca_id, ca_password)

    def generate_crl(self, ca_id: str, ca_password: str) -> CRLResponse:
        """
        Generate or regenerate CRL for a CA.

        Args:
            ca_id: CA identifier
            ca_password: CA private key password

        Returns:
            CRL response with metadata
        """
        ca_dir = self.ca_data_dir / ca_id
        if not ca_dir.exists():
            raise ValueError(f"CA not found: {ca_id}")

        # Verify CA password
        ca_key_path = ca_dir / "ca.key"
        if not self.openssl_service.verify_key_password(ca_key_path, ca_password):
            raise ValueError("Invalid CA password")

        # Initialize CRL files if needed
        self.initialize_crl_files(ca_dir)

        # Load CRL config
        crl_config = self._load_crl_config(ca_dir)

        # Generate CRL using OpenSSL
        cmd = self.openssl_service.build_crl_command(ca_dir, ca_password, crl_config.validity_days)

        success, stdout, stderr = self.openssl_service.execute_command(cmd, ca_dir)
        if not success:
            raise ValueError(f"Failed to generate CRL: {stderr}")

        # Update CRL config
        now = datetime.now()
        crl_config.last_updated = now
        crl_config.next_update = now + timedelta(days=crl_config.validity_days)
        crl_config.crl_number += 1
        self._save_crl_config(ca_dir, crl_config)

        # Convert CRL to DER format as well
        self._convert_crl_to_der(ca_dir)

        return CRLResponse(
            ca_id=ca_id,
            crl_number=crl_config.crl_number,
            created_at=crl_config.created_at,
            next_update=crl_config.next_update,
            revoked_count=len(crl_config.entries),
            last_updated=crl_config.last_updated,
        )

    def get_crl_info(self, ca_id: str) -> Optional[CRLResponse]:
        """Get CRL information for a CA."""
        ca_dir = self.ca_data_dir / ca_id
        crl_config_path = ca_dir / "crl" / "config.yaml"

        if not crl_config_path.exists():
            return None

        crl_config = self._load_crl_config(ca_dir)
        return CRLResponse(
            ca_id=ca_id,
            crl_number=crl_config.crl_number,
            created_at=crl_config.created_at,
            next_update=crl_config.next_update or datetime.now(),
            revoked_count=len(crl_config.entries),
            last_updated=crl_config.last_updated,
        )

    def list_revoked_certificates(self, ca_id: str) -> List[RevocationEntry]:
        """List all revoked certificates for a CA."""
        ca_dir = self.ca_data_dir / ca_id
        crl_config = self._load_crl_config(ca_dir)
        return crl_config.entries

    def _add_to_index(self, ca_dir: Path, cert_config: ServerCertConfig, reason: RevocationReason) -> None:
        """Add revocation entry to OpenSSL index.txt."""
        index_file = ca_dir / "index.txt"

        # Format: V/R<tab>expiry<tab>revocation_date,reason<tab>serial<tab>unknown<tab>subject
        # For revoked: R<tab>expiry<tab>revoke_date,reason<tab>serial<tab>unknown<tab>/CN=...

        revoke_date = datetime.now().strftime("%y%m%d%H%M%SZ")
        expiry_date = cert_config.not_after.strftime("%y%m%d%H%M%SZ")
        serial = cert_config.serial_number.upper()
        # OpenSSL requires even-length hex serial numbers in index.txt
        if len(serial) % 2 != 0:
            serial = "0" + serial
        reason_str = REVOCATION_REASON_CODES.get(reason, "unspecified")
        subject = f"/CN={cert_config.subject.common_name}"
        if cert_config.subject.organization:
            subject += f"/O={cert_config.subject.organization}"

        entry = f"R\t{expiry_date}\t{revoke_date},{reason_str}\t{serial}\tunknown\t{subject}\n"

        # Read existing entries, remove any existing entry for this serial
        existing = ""
        if index_file.exists():
            existing = FileUtils.read_file(index_file)
            lines = [l for l in existing.split("\n") if serial not in l]
            existing = "\n".join(lines)
            if existing and not existing.endswith("\n"):
                existing += "\n"

        FileUtils.write_file(index_file, existing + entry)

    def _remove_from_index(self, ca_dir: Path, serial: str) -> None:
        """Remove entry from OpenSSL index.txt."""
        index_file = ca_dir / "index.txt"
        if not index_file.exists():
            return

        # Pad serial number to even length if needed (to match what we wrote)
        serial_padded = serial.upper()
        if len(serial_padded) % 2 != 0:
            serial_padded = "0" + serial_padded

        content = FileUtils.read_file(index_file)
        lines = [l for l in content.split("\n") if serial_padded not in l]
        FileUtils.write_file(index_file, "\n".join(lines))

    def _load_crl_config(self, ca_dir: Path) -> CRLConfig:
        """Load CRL config from CA directory."""
        crl_config_path = ca_dir / "crl" / "config.yaml"
        if crl_config_path.exists():
            data = YAMLService.load_config_yaml(crl_config_path)
            return CRLConfig(**data)

        ca_id = str(ca_dir.relative_to(self.ca_data_dir))
        return CRLConfig(ca_id=ca_id)

    def _save_crl_config(self, ca_dir: Path, config: CRLConfig) -> None:
        """Save CRL config to CA directory."""
        crl_config_path = ca_dir / "crl" / "config.yaml"
        YAMLService.save_config_yaml(crl_config_path, config.model_dump())

    def _convert_crl_to_der(self, ca_dir: Path) -> None:
        """Convert PEM CRL to DER format."""
        pem_path = ca_dir / "crl" / "crl.pem"
        der_path = ca_dir / "crl" / "crl.der"

        if pem_path.exists():
            cmd = (
                f"openssl crl "
                f"-in {self.openssl_service._path_to_posix(pem_path)} "
                f"-outform DER "
                f"-out {self.openssl_service._path_to_posix(der_path)}"
            )
            self.openssl_service.execute_command(cmd, ca_dir)
