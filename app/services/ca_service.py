"""CA management service."""

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.models.ca import (
    CAConfig,
    CACreateRequest,
    CAResponse,
    CAType,
    IntermediateCAImportRequest,
    RootCAImportRequest,
)
from app.services.openssl_service import OpenSSLService
from app.services.parser_service import CertificateParser
from app.services.yaml_service import YAMLService
from app.utils.file_utils import FileUtils
from app.utils.validators import sanitize_name

logger = logging.getLogger("yacertmanager")


class CAService:
    """Service for CA management operations."""

    def __init__(self, ca_data_dir: Path, openssl_service: OpenSSLService):
        """
        Initialize CA service.

        Args:
            ca_data_dir: Base directory for CA data storage
            openssl_service: OpenSSL service instance
        """
        self.ca_data_dir = ca_data_dir
        self.openssl_service = openssl_service
        FileUtils.ensure_directory(ca_data_dir)

    def create_root_ca(self, request: CACreateRequest) -> CAResponse:
        """
        Create a new Root CA.

        Args:
            request: CA creation request (key_config must include password)

        Returns:
            CA response with created CA details

        Raises:
            ValueError: If CA already exists, password not provided, or creation fails
        """
        # Validate key password is provided
        if not request.key_config.password:
            raise ValueError("Key password is required for CA creation")

        # Sanitize name for directory
        ca_id = f"root-ca-{sanitize_name(request.subject.common_name)}"
        ca_dir = self.ca_data_dir / ca_id

        # Check if already exists
        if ca_dir.exists():
            raise ValueError(f"CA already exists: {ca_id}")

        try:
            # Create directory
            FileUtils.ensure_directory(ca_dir)

            # Create CA config
            ca_config = CAConfig(
                type=CAType.ROOT_CA,
                subject=request.subject,
                key_config=request.key_config,
                validity_days=request.validity_days,
                created_at=datetime.now(),
            )

            # Generate OpenSSL config file
            openssl_cnf = ca_dir / "openssl.cnf"
            self.openssl_service.generate_openssl_config("root_ca", openssl_cnf)

            # Build OpenSSL command
            command = self.openssl_service.build_root_ca_command(ca_config, ca_dir)
            # Store masked command (passwords replaced with ***)
            ca_config.openssl_command = self.openssl_service._mask_password_in_command(command)

            # Execute OpenSSL command
            success, stdout, stderr = self.openssl_service.execute_command(command, ca_dir)
            if not success:
                # Rollback: delete created directory
                FileUtils.delete_directory(ca_dir, ignore_errors=True)
                raise ValueError(f"OpenSSL command failed: {stderr}")

            # Parse created certificate
            cert_path = ca_dir / "ca.crt"
            cert_info = CertificateParser.parse_certificate(cert_path)
            ca_config.fingerprint_sha256 = cert_info["fingerprint_sha256"]
            ca_config.not_before = cert_info["not_before"]
            ca_config.not_after = cert_info["not_after"]

            # Create serial file
            serial_file = ca_dir / "serial"
            FileUtils.write_file(serial_file, "1000\n")

            # Save config.yaml
            config_dict = ca_config.model_dump()
            YAMLService.save_config_yaml(ca_dir / "config.yaml", config_dict)

            logger.info(f"Created Root CA '{request.subject.common_name}' at {ca_dir}")

            # Build response
            return self._build_ca_response(ca_id, ca_config, ca_dir)

        except Exception as e:
            # Rollback on error
            if ca_dir.exists():
                FileUtils.delete_directory(ca_dir, ignore_errors=True)
            logger.error(f"Failed to create Root CA: {e}")
            raise

    def create_intermediate_ca(self, request: CACreateRequest, parent_ca_id: str) -> CAResponse:
        """
        Create a new Intermediate CA under a parent CA.

        Args:
            request: CA creation request (must include parent_ca_password)
            parent_ca_id: ID of parent CA

        Returns:
            CA response with created CA details

        Raises:
            ValueError: If parent CA not found, password not provided, or creation fails
        """
        # Validate key password is provided
        if not request.key_config.password:
            raise ValueError("Key password is required for CA creation")

        # Validate parent CA password is provided
        if not request.parent_ca_password:
            raise ValueError("Parent CA password is required for intermediate CA creation")

        # Validate parent CA exists
        parent_ca_dir = self.ca_data_dir / parent_ca_id
        if not parent_ca_dir.exists():
            raise ValueError(f"Parent CA not found: {parent_ca_id}")

        # Sanitize name for directory
        ca_id = f"{parent_ca_id}/intermediate-ca-{sanitize_name(request.subject.common_name)}"
        ca_dir = self.ca_data_dir / ca_id

        # Check if already exists
        if ca_dir.exists():
            raise ValueError(f"Intermediate CA already exists: {ca_id}")

        try:
            # Create directory
            FileUtils.ensure_directory(ca_dir)

            # Create CA config
            ca_config = CAConfig(
                type=CAType.INTERMEDIATE_CA,
                subject=request.subject,
                key_config=request.key_config,
                validity_days=request.validity_days,
                created_at=datetime.now(),
                parent_ca="..",  # Relative path to parent
            )

            # Generate OpenSSL config file
            openssl_cnf = ca_dir / "openssl.cnf"
            self.openssl_service.generate_openssl_config("intermediate_ca", openssl_cnf)

            # Build OpenSSL command (pass parent CA password for signing)
            command = self.openssl_service.build_intermediate_ca_command(
                ca_config, ca_dir, parent_ca_dir, request.parent_ca_password
            )
            ca_config.openssl_command = self.openssl_service._mask_password_in_command(command)

            # Execute OpenSSL command
            success, stdout, stderr = self.openssl_service.execute_command(command, ca_dir)
            if not success:
                # Rollback: delete created directory
                FileUtils.delete_directory(ca_dir, ignore_errors=True)
                raise ValueError(f"OpenSSL command failed: {stderr}")

            # Parse created certificate
            cert_path = ca_dir / "ca.crt"
            cert_info = CertificateParser.parse_certificate(cert_path)
            ca_config.fingerprint_sha256 = cert_info["fingerprint_sha256"]
            ca_config.not_before = cert_info["not_before"]
            ca_config.not_after = cert_info["not_after"]

            # Create serial file
            serial_file = ca_dir / "serial"
            FileUtils.write_file(serial_file, "1000\n")

            # Cleanup CSR file
            csr_file = ca_dir / "ca.csr"
            if csr_file.exists():
                csr_file.unlink()

            # Save config.yaml
            config_dict = ca_config.model_dump()
            YAMLService.save_config_yaml(ca_dir / "config.yaml", config_dict)

            logger.info(f"Created Intermediate CA '{request.subject.common_name}' under {parent_ca_id}")

            # Build response
            return self._build_ca_response(ca_id, ca_config, ca_dir)

        except Exception as e:
            # Rollback on error
            if ca_dir.exists():
                FileUtils.delete_directory(ca_dir, ignore_errors=True)
            logger.error(f"Failed to create Intermediate CA: {e}")
            raise

    def import_root_ca(self, request: RootCAImportRequest) -> CAResponse:
        """
        Import an external Root CA for tracking.

        Args:
            request: Root CA import request

        Returns:
            CA response with imported CA details

        Raises:
            ValueError: If CA already exists or import fails
        """
        # Sanitize name for directory
        ca_id = f"root-ca-{sanitize_name(request.ca_name)}"
        ca_dir = self.ca_data_dir / ca_id

        # Check if already exists
        if ca_dir.exists():
            raise ValueError(f"CA already exists: {ca_id}")

        try:
            # Create directory
            FileUtils.ensure_directory(ca_dir)

            # Save certificate
            cert_path = ca_dir / "ca.crt"
            FileUtils.write_file(cert_path, request.ca_cert_content)

            # Save private key if provided
            if request.ca_key_content:
                key_path = ca_dir / "ca.key"
                FileUtils.write_file(key_path, request.ca_key_content)

            # Parse certificate to extract information
            cert_info = CertificateParser.parse_certificate(cert_path)

            # Determine key algorithm from parsed info
            algo_map = {"RSA": "RSA", "ECDSA": "ECDSA", "Ed25519": "Ed25519"}
            algorithm = algo_map.get(cert_info.get("public_key_algorithm", "RSA"), "RSA")

            # Build key config from parsed certificate
            from app.models.ca import KeyAlgorithm, KeyConfig

            if algorithm == "RSA":
                key_config = KeyConfig(algorithm=KeyAlgorithm.RSA, key_size=cert_info.get("public_key_size", 2048))
            elif algorithm == "ECDSA":
                from app.models.ca import ECDSACurve

                curve_name = cert_info.get("curve", "P-256")
                key_config = KeyConfig(
                    algorithm=KeyAlgorithm.ECDSA,
                    curve=ECDSACurve(curve_name) if curve_name else ECDSACurve.P256,
                )
            else:  # Ed25519
                key_config = KeyConfig(algorithm=KeyAlgorithm.ED25519)

            # Build subject from parsed certificate
            from app.models.ca import Subject

            subject_data = cert_info["subject"]
            subject = Subject(
                common_name=subject_data.get("CN") or subject_data.get("common_name", "unknown"),
                organization=subject_data.get("O") or subject_data.get("organization"),
                organizational_unit=subject_data.get("OU") or subject_data.get("organizational_unit"),
                country=subject_data.get("C") or subject_data.get("country"),
                state=subject_data.get("ST") or subject_data.get("state"),
                locality=subject_data.get("L") or subject_data.get("locality"),
            )

            # Calculate validity days
            not_before = cert_info["not_before"]
            not_after = cert_info["not_after"]
            validity_days = (not_after - not_before).days

            # Create CA config
            ca_config = CAConfig(
                type=CAType.ROOT_CA,
                subject=subject,
                key_config=key_config,
                validity_days=validity_days,
                created_at=datetime.now(),
                not_before=not_before,
                not_after=not_after,
                fingerprint_sha256=cert_info["fingerprint_sha256"],
                openssl_command="# Imported external Root CA",
            )

            # Create serial file
            serial_file = ca_dir / "serial"
            FileUtils.write_file(serial_file, "1000\n")

            # Save config.yaml
            config_dict = ca_config.model_dump()
            YAMLService.save_config_yaml(ca_dir / "config.yaml", config_dict)

            logger.info(f"Imported Root CA '{subject.common_name}' at {ca_dir}")

            # Build response
            return self._build_ca_response(ca_id, ca_config, ca_dir)

        except Exception as e:
            # Rollback on error
            if ca_dir.exists():
                FileUtils.delete_directory(ca_dir, ignore_errors=True)
            logger.error(f"Failed to import Root CA: {e}")
            raise ValueError(f"Failed to import Root CA: {e}")

    def import_intermediate_ca(self, request: IntermediateCAImportRequest) -> CAResponse:
        """
        Import an external Intermediate CA for tracking.

        Args:
            request: Intermediate CA import request

        Returns:
            CA response with imported CA details

        Raises:
            ValueError: If parent CA not found, CA already exists, or import fails
        """
        # Verify parent CA exists
        parent_ca_dir = self.ca_data_dir / request.parent_ca_id
        if not parent_ca_dir.exists():
            raise ValueError(f"Parent CA not found: {request.parent_ca_id}")

        # Sanitize name for directory
        ca_name = sanitize_name(request.ca_name)
        ca_id = f"{request.parent_ca_id}/intermediate-ca-{ca_name}"
        ca_dir = self.ca_data_dir / request.parent_ca_id / f"intermediate-ca-{ca_name}"

        # Check if already exists
        if ca_dir.exists():
            raise ValueError(f"Intermediate CA already exists: {ca_id}")

        try:
            # Create directory
            FileUtils.ensure_directory(ca_dir)

            # Save certificate
            cert_path = ca_dir / "ca.crt"
            FileUtils.write_file(cert_path, request.ca_cert_content)

            # Save private key if provided
            if request.ca_key_content:
                key_path = ca_dir / "ca.key"
                FileUtils.write_file(key_path, request.ca_key_content)

            # Parse certificate to extract information
            cert_info = CertificateParser.parse_certificate(cert_path)

            # Determine key algorithm from parsed info
            algo_map = {"RSA": "RSA", "ECDSA": "ECDSA", "Ed25519": "Ed25519"}
            algorithm = algo_map.get(cert_info.get("public_key_algorithm", "RSA"), "RSA")

            # Build key config from parsed certificate
            from app.models.ca import KeyAlgorithm, KeyConfig

            if algorithm == "RSA":
                key_config = KeyConfig(algorithm=KeyAlgorithm.RSA, key_size=cert_info.get("public_key_size", 2048))
            elif algorithm == "ECDSA":
                from app.models.ca import ECDSACurve

                curve_name = cert_info.get("curve", "P-256")
                key_config = KeyConfig(
                    algorithm=KeyAlgorithm.ECDSA,
                    curve=ECDSACurve(curve_name) if curve_name else ECDSACurve.P256,
                )
            else:  # Ed25519
                key_config = KeyConfig(algorithm=KeyAlgorithm.ED25519)

            # Build subject from parsed certificate
            from app.models.ca import Subject

            subject_data = cert_info["subject"]
            subject = Subject(
                common_name=subject_data.get("CN") or subject_data.get("common_name", "unknown"),
                organization=subject_data.get("O") or subject_data.get("organization"),
                organizational_unit=subject_data.get("OU") or subject_data.get("organizational_unit"),
                country=subject_data.get("C") or subject_data.get("country"),
                state=subject_data.get("ST") or subject_data.get("state"),
                locality=subject_data.get("L") or subject_data.get("locality"),
            )

            # Calculate validity days
            not_before = cert_info["not_before"]
            not_after = cert_info["not_after"]
            validity_days = (not_after - not_before).days

            # Create CA config
            ca_config = CAConfig(
                type=CAType.INTERMEDIATE_CA,
                subject=subject,
                key_config=key_config,
                validity_days=validity_days,
                created_at=datetime.now(),
                not_before=not_before,
                not_after=not_after,
                fingerprint_sha256=cert_info["fingerprint_sha256"],
                parent_ca=request.parent_ca_id,
                openssl_command="# Imported external Intermediate CA",
            )

            # Create serial file
            serial_file = ca_dir / "serial"
            FileUtils.write_file(serial_file, "1000\n")

            # Create certs directory
            certs_dir = ca_dir / "certs"
            FileUtils.ensure_directory(certs_dir)

            # Save config.yaml
            config_dict = ca_config.model_dump()
            YAMLService.save_config_yaml(ca_dir / "config.yaml", config_dict)

            logger.info(f"Imported Intermediate CA '{subject.common_name}' under {request.parent_ca_id}")

            # Build response
            return self._build_ca_response(ca_id, ca_config, ca_dir)

        except Exception as e:
            # Rollback on error
            if ca_dir.exists():
                FileUtils.delete_directory(ca_dir, ignore_errors=True)
            logger.error(f"Failed to import Intermediate CA: {e}")
            raise ValueError(f"Failed to import Intermediate CA: {e}")

    def list_root_cas(self) -> List[CAResponse]:
        """
        List all root CAs.

        Returns:
            List of root CA responses
        """
        root_cas = []

        for ca_dir in FileUtils.list_directories(self.ca_data_dir):
            if ca_dir.name.startswith("root-ca-"):
                try:
                    ca_response = self.get_ca(ca_dir.name)
                    root_cas.append(ca_response)
                except Exception as e:
                    logger.warning(f"Failed to load CA {ca_dir.name}: {e}")

        return root_cas

    def list_all_intermediate_cas(self) -> List[CAResponse]:
        """
        List all intermediate CAs across all root CAs, including nested intermediates.

        Returns:
            List of intermediate CA responses
        """
        intermediate_cas = []

        # Iterate through all root CAs
        for root_ca_dir in FileUtils.list_directories(self.ca_data_dir):
            if root_ca_dir.name.startswith("root-ca-"):
                # Recursively find all intermediate CAs under this root CA
                self._collect_intermediate_cas_recursive(root_ca_dir, root_ca_dir.name, intermediate_cas)

        return intermediate_cas

    def _collect_intermediate_cas_recursive(
        self, parent_dir: Path, parent_id: str, result_list: List[CAResponse]
    ) -> None:
        """
        Recursively collect all intermediate CAs under a parent directory.

        Args:
            parent_dir: Parent CA directory
            parent_id: Parent CA ID (for building full path)
            result_list: List to append found CAs to
        """
        for sub_dir in FileUtils.list_directories(parent_dir):
            if sub_dir.name.startswith("intermediate-ca-"):
                intermediate_id = f"{parent_id}/{sub_dir.name}"
                try:
                    ca_response = self.get_ca(intermediate_id)
                    result_list.append(ca_response)
                except Exception as e:
                    logger.warning(f"Failed to load intermediate CA {intermediate_id}: {e}")

                # Recursively search for nested intermediates
                self._collect_intermediate_cas_recursive(sub_dir, intermediate_id, result_list)

    def get_ca(self, ca_id: str) -> CAResponse:
        """
        Get CA details by ID.

        Args:
            ca_id: CA identifier

        Returns:
            CA response

        Raises:
            ValueError: If CA not found
        """
        ca_dir = self.ca_data_dir / ca_id
        if not ca_dir.exists():
            raise ValueError(f"CA not found: {ca_id}")

        # Load config
        config_path = ca_dir / "config.yaml"
        if not config_path.exists():
            raise ValueError(f"CA config not found: {ca_id}")

        config_data = YAMLService.load_config_yaml(config_path)
        ca_config = CAConfig(**config_data)

        return self._build_ca_response(ca_id, ca_config, ca_dir)

    def delete_ca(self, ca_id: str) -> None:
        """
        Delete CA by moving it to trash.

        Moves the CA and all its contents to a _trash folder at the same
        directory level with a timestamp suffix.

        Args:
            ca_id: CA identifier

        Raises:
            ValueError: If CA not found
        """
        ca_dir = self.ca_data_dir / ca_id
        if not ca_dir.exists():
            raise ValueError(f"CA not found: {ca_id}")

        # Count intermediate CAs and certificates
        intermediate_count = len(self._count_intermediate_cas(ca_dir))
        cert_count = self._count_certificates(ca_dir)

        # Move to trash instead of permanent deletion
        trash_path = FileUtils.move_to_trash(ca_dir)

        logger.warning(
            f"Moved CA '{ca_id}' to trash including {intermediate_count} intermediate CAs "
            f"and {cert_count} certificates -> {trash_path}"
        )

    def _build_ca_response(self, ca_id: str, ca_config: CAConfig, ca_dir: Path) -> CAResponse:
        """
        Build CA response from config and directory.

        Args:
            ca_id: CA identifier
            ca_config: CA configuration
            ca_dir: CA directory path

        Returns:
            CA response
        """
        # Count intermediate CAs and certificates
        intermediate_count = len(self._count_intermediate_cas(ca_dir))
        cert_count = self._count_certificates(ca_dir)

        # Get validity status
        status_class, status_text = CertificateParser.get_validity_status(ca_config.not_before, ca_config.not_after)

        # Parse extensions from certificate
        key_usage = []
        extended_key_usage = []
        cert_path = ca_dir / "ca.crt"
        if cert_path.exists():
            try:
                cert_info = CertificateParser.parse_certificate(cert_path)
                key_usage = cert_info.get("key_usage", [])
                extended_key_usage = cert_info.get("extended_key_usage", [])
            except Exception as e:
                logger.warning(f"Failed to parse extensions for CA {ca_id}: {e}")

        return CAResponse(
            id=ca_id,
            path=str(ca_dir),
            type=ca_config.type,
            subject=ca_config.subject,
            not_before=ca_config.not_before,
            not_after=ca_config.not_after,
            fingerprint_sha256=ca_config.fingerprint_sha256,
            openssl_command=ca_config.openssl_command,
            intermediate_count=intermediate_count,
            cert_count=cert_count,
            validity_status=status_class,
            validity_text=status_text,
            key_usage=key_usage,
            extended_key_usage=extended_key_usage,
        )

    def _count_intermediate_cas(self, ca_dir: Path) -> List[Path]:
        """
        Count intermediate CAs under a CA directory (recursively).

        Args:
            ca_dir: CA directory

        Returns:
            List of all intermediate CA directories (including nested)
        """
        intermediates = []
        for sub_dir in FileUtils.list_directories(ca_dir):
            if sub_dir.name.startswith("intermediate-ca-"):
                intermediates.append(sub_dir)
                # Recursively count nested intermediates
                intermediates.extend(self._count_intermediate_cas(sub_dir))
        return intermediates

    def _count_certificates(self, ca_dir: Path) -> int:
        """
        Count certificates under a CA directory (recursively).

        Args:
            ca_dir: CA directory

        Returns:
            Number of certificates
        """
        count = 0

        # Check for certs directory
        certs_dir = ca_dir / "certs"
        if certs_dir.exists():
            count += len(FileUtils.list_directories(certs_dir))

        # Recursively check intermediate CAs
        for intermediate_dir in self._count_intermediate_cas(ca_dir):
            count += self._count_certificates(intermediate_dir)

        return count

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about CAs and certificates.

        Returns:
            Dictionary with statistics
        """
        root_cas = self.list_root_cas()
        total_intermediates = sum(ca.intermediate_count for ca in root_cas)
        total_certs = sum(ca.cert_count for ca in root_cas)

        # Count expiring soon (within 30 days)
        expiring_soon = 0
        for ca in root_cas:
            if ca.validity_status == "warning":
                expiring_soon += 1

        return {
            "root_cas": len(root_cas),
            "intermediate_cas": total_intermediates,
            "certificates": total_certs,
            "expiring_soon": expiring_soon,
        }
