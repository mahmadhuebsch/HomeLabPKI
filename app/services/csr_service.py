"""CSR (Certificate Signing Request) management service."""

import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from app.models.ca import KeyConfig
from app.models.certificate import (
    CSRConfig,
    CSRCreateRequest,
    CSRResponse,
    CSRSignedRequest,
    CSRStatus,
)
from app.services.openssl_service import OpenSSLService
from app.services.parser_service import CertificateParser
from app.services.yaml_service import YAMLService
from app.utils.file_utils import FileUtils
from app.utils.validators import sanitize_name

logger = logging.getLogger("homelabpki")


class CSRService:
    """Service for CSR management operations."""

    def __init__(self, ca_data_dir: Path, openssl_service: OpenSSLService):
        """
        Initialize CSR service.

        Args:
            ca_data_dir: Base directory for CA data storage
            openssl_service: OpenSSL service instance
        """
        self.ca_data_dir = ca_data_dir
        self.openssl_service = openssl_service
        self.csrs_dir = ca_data_dir / "csrs"

        # Ensure CSRs directory exists
        FileUtils.ensure_directory(self.csrs_dir)

    def create_csr(self, request: CSRCreateRequest) -> CSRResponse:
        """
        Create a new CSR and encrypted private key.

        Args:
            request: CSR creation request with key_password (not stored)

        Returns:
            CSR response

        Raises:
            ValueError: If password not provided or creation fails
        """
        # Validate key password is provided
        if not request.key_password:
            raise ValueError("Key password is required for CSR creation")

        # Sanitize CN for directory name
        cn = request.subject.common_name
        csr_id = sanitize_name(cn)
        csr_dir = self.csrs_dir / csr_id

        # Check if already exists
        if csr_dir.exists():
            raise ValueError(f"CSR already exists for: {cn}")

        try:
            # Create directory
            FileUtils.ensure_directory(csr_dir)

            # Build KeyConfig with encrypted=True (password NOT stored)
            key_config = KeyConfig(
                algorithm=request.key_algorithm,
                key_size=request.key_size,
                curve=request.key_curve,
                encrypted=True,
            )

            # Create CSR config
            csr_config = CSRConfig(
                type="csr",
                created_at=datetime.now(),
                subject=request.subject,
                sans=request.sans or [cn],
                key_config=key_config,
                target_ca=request.target_ca,
                status=CSRStatus.PENDING,
                key_usage=request.key_usage,
                extended_key_usage=request.extended_key_usage,
            )

            # Generate SAN config file with extensions
            san_cnf = csr_dir / "san.cnf"
            self.openssl_service.generate_openssl_config(
                "server_cert",
                san_cnf,
                csr_config.sans,
                csr_config.key_usage,
                csr_config.extended_key_usage,
            )

            # Build OpenSSL command for CSR creation
            command = self.openssl_service.build_csr_command(
                request.subject,
                request.sans or [cn],
                key_config,
                csr_dir,
                request.key_password,
                request.key_usage,
                request.extended_key_usage,
            )

            # Store masked command (passwords replaced with ***)
            csr_config.openssl_command = self.openssl_service._mask_password_in_command(command)

            # Execute OpenSSL command
            success, stdout, stderr = self.openssl_service.execute_command(command, csr_dir)
            if not success:
                # Rollback: delete created directory
                FileUtils.delete_directory(csr_dir, ignore_errors=True)
                raise ValueError(f"OpenSSL command failed: {stderr}")

            # Get CSR public key fingerprint for matching
            csr_path = csr_dir / "csr.pem"
            csr_config.fingerprint_sha256 = CertificateParser.get_csr_public_key_fingerprint(csr_path)

            # Cleanup temporary config file
            if san_cnf.exists():
                san_cnf.unlink()

            # Save config.yaml (WITHOUT password)
            config_path = csr_dir / "config.yaml"
            YAMLService.save_config_yaml(config_path, csr_config.model_dump())

            logger.info(f"CSR created successfully: {csr_id}")

            # Return response
            return CSRResponse(
                id=csr_id,
                path=str(csr_dir),
                subject=csr_config.subject,
                sans=csr_config.sans,
                status=csr_config.status,
                created_at=csr_config.created_at,
                target_ca=csr_config.target_ca,
                openssl_command=csr_config.openssl_command,
                fingerprint_sha256=csr_config.fingerprint_sha256,
                key_usage=csr_config.key_usage,
                extended_key_usage=csr_config.extended_key_usage,
            )

        except Exception as e:
            logger.error(f"CSR creation failed: {e}")
            # Ensure cleanup on error
            if csr_dir.exists():
                FileUtils.delete_directory(csr_dir, ignore_errors=True)
            raise

    def get_csr(self, csr_id: str) -> CSRResponse:
        """
        Get CSR details by ID.

        Args:
            csr_id: CSR identifier

        Returns:
            CSR response

        Raises:
            ValueError: If CSR not found
        """
        csr_dir = self.csrs_dir / csr_id
        if not csr_dir.exists():
            raise ValueError(f"CSR not found: {csr_id}")

        # Load config
        config_path = csr_dir / "config.yaml"
        if not config_path.exists():
            raise ValueError(f"CSR config not found: {csr_id}")

        config_data = YAMLService.load_config_yaml(config_path)
        csr_config = CSRConfig(**config_data)

        return CSRResponse(
            id=csr_id,
            path=str(csr_dir),
            subject=csr_config.subject,
            sans=csr_config.sans,
            status=csr_config.status,
            created_at=csr_config.created_at,
            target_ca=csr_config.target_ca,
            openssl_command=csr_config.openssl_command,
            fingerprint_sha256=csr_config.fingerprint_sha256,
            key_usage=csr_config.key_usage,
            extended_key_usage=csr_config.extended_key_usage,
        )

    def list_csrs(self, status_filter: Optional[CSRStatus] = None) -> List[CSRResponse]:
        """
        List all CSRs with optional status filter.

        Args:
            status_filter: Optional status to filter by

        Returns:
            List of CSR responses
        """
        csrs = []

        # Ensure CSRs directory exists
        if not self.csrs_dir.exists():
            return csrs

        # Iterate through CSR directories (exclude _trash)
        for csr_dir in self.csrs_dir.iterdir():
            if not csr_dir.is_dir() or csr_dir.name.startswith("_"):
                continue

            try:
                config_path = csr_dir / "config.yaml"
                if not config_path.exists():
                    continue

                config_data = YAMLService.load_config_yaml(config_path)
                csr_config = CSRConfig(**config_data)

                # Apply status filter if provided
                if status_filter is not None and csr_config.status != status_filter:
                    continue

                csrs.append(
                    CSRResponse(
                        id=csr_dir.name,
                        path=str(csr_dir),
                        subject=csr_config.subject,
                        sans=csr_config.sans,
                        status=csr_config.status,
                        created_at=csr_config.created_at,
                        target_ca=csr_config.target_ca,
                        openssl_command=csr_config.openssl_command,
                        fingerprint_sha256=csr_config.fingerprint_sha256,
                        key_usage=csr_config.key_usage,
                        extended_key_usage=csr_config.extended_key_usage,
                    )
                )

            except Exception as e:
                logger.warning(f"Error loading CSR {csr_dir.name}: {e}")
                continue

        # Sort by created_at (newest first)
        csrs.sort(key=lambda x: x.created_at, reverse=True)

        return csrs

    def delete_csr(self, csr_id: str) -> None:
        """
        Delete CSR (soft delete - move to trash).

        Args:
            csr_id: CSR identifier

        Raises:
            ValueError: If CSR not found
        """
        csr_dir = self.csrs_dir / csr_id
        if not csr_dir.exists():
            raise ValueError(f"CSR not found: {csr_id}")

        # Create trash directory if not exists
        trash_dir = self.csrs_dir / "_trash"
        FileUtils.ensure_directory(trash_dir)

        # Generate unique trash name with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        trash_name = f"{csr_id}_{timestamp}"
        trash_path = trash_dir / trash_name

        # Move to trash
        shutil.move(str(csr_dir), str(trash_path))

        logger.info(f"CSR deleted (moved to trash): {csr_id}")

    def mark_signed(self, csr_id: str, request: CSRSignedRequest) -> CSRResponse:
        """
        Import signed certificate for a CSR and update status.

        Args:
            csr_id: CSR identifier
            request: Signed certificate import request

        Returns:
            Updated CSR response

        Raises:
            ValueError: If CSR not found, certificate doesn't match CSR, or import fails
        """
        csr_dir = self.csrs_dir / csr_id
        if not csr_dir.exists():
            raise ValueError(f"CSR not found: {csr_id}")

        # Load config
        config_path = csr_dir / "config.yaml"
        if not config_path.exists():
            raise ValueError(f"CSR config not found: {csr_id}")

        config_data = YAMLService.load_config_yaml(config_path)
        csr_config = CSRConfig(**config_data)

        try:
            # Write certificate to file
            cert_path = csr_dir / "cert.pem"
            with open(cert_path, "w") as f:
                f.write(request.cert_content)

            # Verify certificate matches CSR public key
            csr_path = csr_dir / "csr.pem"
            if not CertificateParser.verify_cert_matches_csr(cert_path, csr_path):
                # Cleanup invalid certificate
                cert_path.unlink()
                raise ValueError(
                    "Certificate does not match CSR public key. " "The certificate must be signed from this CSR."
                )

            # Write chain if provided
            if request.chain_content:
                chain_path = csr_dir / "chain.pem"
                with open(chain_path, "w") as f:
                    f.write(request.chain_content)

            # Update status to signed
            csr_config.status = CSRStatus.SIGNED

            # Save updated config
            YAMLService.save_config_yaml(config_path, csr_config.model_dump())

            logger.info(f"Signed certificate imported for CSR: {csr_id}")

            return CSRResponse(
                id=csr_id,
                path=str(csr_dir),
                subject=csr_config.subject,
                sans=csr_config.sans,
                status=csr_config.status,
                created_at=csr_config.created_at,
                target_ca=csr_config.target_ca,
                openssl_command=csr_config.openssl_command,
                fingerprint_sha256=csr_config.fingerprint_sha256,
                key_usage=csr_config.key_usage,
                extended_key_usage=csr_config.extended_key_usage,
            )

        except Exception as e:
            logger.error(f"Signed certificate import failed: {e}")
            raise

    def get_csr_content(self, csr_id: str) -> str:
        """
        Get CSR PEM content.

        Args:
            csr_id: CSR identifier

        Returns:
            PEM-encoded CSR content

        Raises:
            ValueError: If CSR not found
        """
        csr_dir = self.csrs_dir / csr_id
        csr_path = csr_dir / "csr.pem"

        if not csr_path.exists():
            raise ValueError(f"CSR file not found: {csr_id}")

        return FileUtils.read_file(csr_path)
