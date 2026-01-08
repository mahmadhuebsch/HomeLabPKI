"""CA management service."""

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, ed25519

from app.models.ca import (
    CAConfig,
    CACreateRequest,
    CAResponse,
    CAType,
    ChainImportRequest,
    ChainImportResponse,
    ECDSACurve,
    IntermediateCAImportRequest,
    KeyAlgorithm,
    KeyConfig,
    RootCAImportRequest,
    Subject,
)
from app.services.openssl_service import OpenSSLService
from app.services.parser_service import CertificateParser
from app.services.yaml_service import YAMLService
from app.utils.file_utils import FileUtils
from app.utils.validators import sanitize_name

logger = logging.getLogger("homelabpki")


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
            request: CA creation request with key_password (not stored)
        Returns:
            CA response with created CA details
        Raises:
            ValueError: If CA already exists, password not provided, or creation fails
        """
        if not request.key_password:
            raise ValueError("Key password is required for CA creation")

        ca_id = f"root-ca-{sanitize_name(request.subject.common_name)}"
        ca_dir = self.ca_data_dir / ca_id
        if ca_dir.exists():
            raise ValueError(f"CA already exists: {ca_id}")

        try:
            FileUtils.ensure_directory(ca_dir)

            # Build KeyConfig with encrypted=True (password NOT stored)
            key_config = KeyConfig(
                algorithm=request.key_algorithm,
                key_size=request.key_size,
                curve=request.key_curve,
                encrypted=True,
            )

            ca_config = CAConfig(
                type=CAType.ROOT_CA,
                subject=request.subject,
                key_config=key_config,
                validity_days=request.validity_days,
                created_at=datetime.now(),
            )

            openssl_cnf = ca_dir / "openssl.cnf"
            self.openssl_service.generate_openssl_config("root_ca", openssl_cnf)

            # Pass password to OpenSSL service (not stored in config)
            command = self.openssl_service.build_root_ca_command(ca_config, ca_dir, request.key_password)
            ca_config.openssl_command = self.openssl_service._mask_password_in_command(command)

            success, stdout, stderr = self.openssl_service.execute_command(command, ca_dir)
            if not success:
                FileUtils.delete_directory(ca_dir, ignore_errors=True)
                raise ValueError(f"OpenSSL command failed: {stderr}")

            cert_path = ca_dir / "ca.crt"
            cert_info = CertificateParser.parse_certificate(cert_path)
            ca_config.fingerprint_sha256 = cert_info["fingerprint_sha256"]
            ca_config.not_before = cert_info["not_before"]
            ca_config.not_after = cert_info["not_after"]

            FileUtils.write_file(ca_dir / "serial", "1000\n")
            config_dict = ca_config.model_dump()
            YAMLService.save_config_yaml(ca_dir / "config.yaml", config_dict)

            logger.info(f"Created Root CA '{request.subject.common_name}' at {ca_dir}")
            return self._build_ca_response(ca_id, ca_config, ca_dir)

        except Exception as e:
            if ca_dir.exists():
                FileUtils.delete_directory(ca_dir, ignore_errors=True)
            logger.error(f"Failed to create Root CA: {e}")
            raise

    def create_intermediate_ca(self, request: CACreateRequest, parent_ca_id: str) -> CAResponse:
        """
        Create a new Intermediate CA under a parent CA.
        Args:
            request: CA creation request with key_password and parent_ca_password (not stored)
            parent_ca_id: ID of parent CA
        Returns:
            CA response with created CA details
        Raises:
            ValueError: If parent CA not found, password not provided/invalid, or creation fails
        """
        if not request.key_password:
            raise ValueError("Key password is required for CA creation")
        if not request.parent_ca_password:
            raise ValueError("Parent CA password is required for intermediate CA creation")

        parent_ca_dir = self.ca_data_dir / parent_ca_id
        if not parent_ca_dir.exists():
            raise ValueError(f"Parent CA not found: {parent_ca_id}")

        # Verify parent CA password before proceeding
        parent_key_path = parent_ca_dir / "ca.key"
        if parent_key_path.exists():
            if not self.openssl_service.verify_key_password(parent_key_path, request.parent_ca_password):
                raise ValueError("Invalid password for parent CA private key")

        ca_id = f"{parent_ca_id}/intermediate-ca-{sanitize_name(request.subject.common_name)}"
        ca_dir = self.ca_data_dir / ca_id
        if ca_dir.exists():
            raise ValueError(f"Intermediate CA already exists: {ca_id}")

        try:
            FileUtils.ensure_directory(ca_dir)

            # Build KeyConfig with encrypted=True (password NOT stored)
            key_config = KeyConfig(
                algorithm=request.key_algorithm,
                key_size=request.key_size,
                curve=request.key_curve,
                encrypted=True,
            )

            ca_config = CAConfig(
                type=CAType.INTERMEDIATE_CA,
                subject=request.subject,
                key_config=key_config,
                validity_days=request.validity_days,
                created_at=datetime.now(),
                parent_ca="..",
            )

            openssl_cnf = ca_dir / "openssl.cnf"
            self.openssl_service.generate_openssl_config("intermediate_ca", openssl_cnf)

            # Pass passwords to OpenSSL service (not stored in config)
            command = self.openssl_service.build_intermediate_ca_command(
                ca_config, ca_dir, parent_ca_dir, request.key_password, request.parent_ca_password
            )
            ca_config.openssl_command = self.openssl_service._mask_password_in_command(command)

            success, stdout, stderr = self.openssl_service.execute_command(command, ca_dir)
            if not success:
                FileUtils.delete_directory(ca_dir, ignore_errors=True)
                raise ValueError(f"OpenSSL command failed: {stderr}")

            cert_path = ca_dir / "ca.crt"
            cert_info = CertificateParser.parse_certificate(cert_path)
            ca_config.fingerprint_sha256 = cert_info["fingerprint_sha256"]
            ca_config.not_before = cert_info["not_before"]
            ca_config.not_after = cert_info["not_after"]

            FileUtils.write_file(ca_dir / "serial", "1000\n")
            csr_file = ca_dir / "ca.csr"
            if csr_file.exists():
                csr_file.unlink()

            config_dict = ca_config.model_dump()
            YAMLService.save_config_yaml(ca_dir / "config.yaml", config_dict)

            logger.info(f"Created Intermediate CA '{request.subject.common_name}' under {parent_ca_id}")
            return self._build_ca_response(ca_id, ca_config, ca_dir)

        except Exception as e:
            if ca_dir.exists():
                FileUtils.delete_directory(ca_dir, ignore_errors=True)
            logger.error(f"Failed to create Intermediate CA: {e}")
            raise

    def _find_ca_by_fingerprint(self, fingerprint: str) -> Optional[str]:
        """Find an existing CA by its SHA-256 fingerprint."""
        for ca_dir in self.ca_data_dir.rglob("*"):
            if not ca_dir.is_dir() or not ca_dir.name.startswith(("root-ca-", "intermediate-ca-")):
                continue
            # Exclude trash directories
            relative_path = str(ca_dir.relative_to(self.ca_data_dir)).replace("\\", "/")
            if "_trash" in relative_path:
                continue
            config_path = ca_dir / "config.yaml"
            if config_path.exists():
                try:
                    config_data = YAMLService.load_config_yaml(config_path)
                    if config_data.get("fingerprint_sha256") == fingerprint:
                        return relative_path
                except Exception:
                    continue
        return None

    def _perform_ca_import(
        self,
        cert: x509.Certificate,
        ca_name: str,
        ca_id: str,
        ca_type: CAType,
        pem_content: str,
        parent_ca_id: Optional[str] = None,
    ) -> CAResponse:
        """Internal method to perform the filesystem import of a single CA."""
        ca_dir = self.ca_data_dir / ca_id
        try:
            FileUtils.ensure_directory(ca_dir)
            cert_path = ca_dir / "ca.crt"
            FileUtils.write_file(cert_path, pem_content)
            cert_info = CertificateParser.parse_certificate_pem(pem_content)

            key_info = CertificateParser._extract_key_info(cert.public_key())
            key_config = KeyConfig(
                algorithm=key_info["algorithm"],
                key_size=key_info.get("key_size"),
                curve=key_info.get("curve"),
                encrypted=False,  # Imported CAs don't have keys managed by us
            )

            subject_info = CertificateParser._extract_subject(cert.subject)
            subject = Subject(
                common_name=subject_info.get("common_name", "unknown"),
                organization=subject_info.get("organization"),
                organizational_unit=subject_info.get("organizational_unit"),
                country=subject_info.get("country"),
                state=subject_info.get("state"),
                locality=subject_info.get("locality"),
            )
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
            validity_days = (not_after - not_before).days
            parent_rel_path = ".." if ca_type == CAType.INTERMEDIATE_CA else None

            ca_config = CAConfig(
                type=ca_type,
                subject=subject,
                key_config=key_config,
                validity_days=validity_days,
                created_at=datetime.now(),
                not_before=not_before,
                not_after=not_after,
                fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex().upper(),
                parent_ca=parent_rel_path,
                openssl_command="# Imported external CA",
            )
            FileUtils.write_file(ca_dir / "serial", "1000\n")
            if ca_type == CAType.INTERMEDIATE_CA:
                FileUtils.ensure_directory(ca_dir / "certs")
            YAMLService.save_config_yaml(ca_dir / "config.yaml", ca_config.model_dump())
            logger.info(f"Imported {ca_type.value} '{subject.common_name}' at {ca_dir}")
            return self._build_ca_response(ca_id, ca_config, ca_dir)
        except Exception as e:
            if ca_dir.exists():
                FileUtils.delete_directory(ca_dir, ignore_errors=True)
            logger.error(f"Failed to perform import for CA '{ca_name}': {e}")
            raise ValueError(f"Failed to import CA '{ca_name}': {e}")

    def import_root_ca(self, request: RootCAImportRequest) -> CAResponse:
        """Import a single self-signed Root CA certificate."""
        pem_certs = CertificateParser.split_pem_bundle(request.ca_cert_content)
        if not pem_certs:
            raise ValueError("Certificate content is empty or invalid.")
        if len(pem_certs) > 1:
            raise ValueError("Please provide a single certificate. Multiple certificates are not supported.")

        cert = CertificateParser.load_pem_x509_certificate_from_string(pem_certs[0])

        if not CertificateParser._is_ca(cert):
            raise ValueError("The provided certificate is not a CA certificate (missing CA:TRUE in Basic Constraints).")

        if cert.subject != cert.issuer:
            raise ValueError(
                "The provided certificate is not a self-signed Root CA. "
                "For intermediate CAs, use the 'Import Intermediate CA' feature."
            )

        fingerprint = cert.fingerprint(hashes.SHA256()).hex().upper()
        if self._find_ca_by_fingerprint(fingerprint):
            raise ValueError("A CA with this fingerprint already exists.")

        ca_id = f"root-ca-{sanitize_name(request.ca_name)}"
        if (self.ca_data_dir / ca_id).exists():
            raise ValueError(f"A CA with the name '{request.ca_name}' already exists.")

        return self._perform_ca_import(cert, request.ca_name, ca_id, CAType.ROOT_CA, pem_certs[0])

    def import_intermediate_ca(self, request: IntermediateCAImportRequest) -> CAResponse:
        """Import a single Intermediate CA certificate under an existing parent CA."""
        # Validate parent_ca_id is provided
        if not request.parent_ca_id:
            raise ValueError("Parent CA ID is required. Please select the issuing CA for this intermediate.")

        parent_ca_dir = self.ca_data_dir / request.parent_ca_id
        if not parent_ca_dir.exists():
            raise ValueError(f"Parent CA not found: {request.parent_ca_id}")

        # Parse and validate certificate
        pem_certs = CertificateParser.split_pem_bundle(request.ca_cert_content)
        if not pem_certs:
            raise ValueError("Certificate content is empty or invalid.")
        if len(pem_certs) > 1:
            raise ValueError("Please provide a single certificate. Multiple certificates are not supported.")

        cert = CertificateParser.load_pem_x509_certificate_from_string(pem_certs[0])

        if not CertificateParser._is_ca(cert):
            raise ValueError("The provided certificate is not a CA certificate (missing CA:TRUE in Basic Constraints).")

        if cert.subject == cert.issuer:
            raise ValueError(
                "The provided certificate is a self-signed Root CA. " "Please use the 'Import Root CA' feature instead."
            )

        # Check for duplicate
        fingerprint = cert.fingerprint(hashes.SHA256()).hex().upper()
        existing_ca_id = self._find_ca_by_fingerprint(fingerprint)
        if existing_ca_id:
            raise ValueError(f"This CA certificate already exists at: {existing_ca_id}")

        # Build CA ID and check for name collision
        ca_id = f"{request.parent_ca_id}/intermediate-ca-{sanitize_name(request.ca_name)}"
        if (self.ca_data_dir / ca_id).exists():
            raise ValueError(f"A CA with the name '{request.ca_name}' already exists under this parent.")

        return self._perform_ca_import(
            cert, request.ca_name, ca_id, CAType.INTERMEDIATE_CA, pem_certs[0], request.parent_ca_id
        )

    def import_certificate_chain(
        self, request: ChainImportRequest, cert_service: "CertificateService" = None
    ) -> ChainImportResponse:
        """
        Import a complete certificate chain (root CA + intermediate CAs + leaf certificates).

        The chain is validated to ensure:
        - It contains a self-signed root CA
        - All certificates form a valid chain (proper issuer relationships)
        - All signatures are valid

        Args:
            request: Chain import request containing the PEM bundle
            cert_service: Optional certificate service for importing leaf certificates

        Returns:
            ChainImportResponse with list of imported CAs and certificates

        Raises:
            ValueError: If chain is invalid or import fails
        """
        from cryptography.hazmat.primitives.serialization import Encoding

        # Validate and order the chain
        ordered_chain, errors = CertificateParser.validate_certificate_chain(request.chain_content)

        if errors:
            raise ValueError("Chain validation failed:\n" + "\n".join(f"- {e}" for e in errors))

        # Separate CA certificates from leaf certificates
        ca_certs = []
        leaf_certs = []
        for cert in ordered_chain:
            if CertificateParser._is_ca(cert):
                ca_certs.append(cert)
            else:
                leaf_certs.append(cert)

        if not ca_certs:
            raise ValueError("No CA certificates found in the chain. At least a root CA is required.")

        imported_cas = []
        imported_cert_ids = []

        # Build a mapping of certificate fingerprints to CA IDs for finding issuers
        fingerprint_to_ca_id = {}

        # Import root CA (first in ca_certs list)
        root_cert = ca_certs[0]
        root_cn = CertificateParser._get_cn(root_cert)
        root_fingerprint = root_cert.fingerprint(hashes.SHA256()).hex().upper()

        # Check if root already exists
        existing_root_id = self._find_ca_by_fingerprint(root_fingerprint)
        if existing_root_id:
            root_ca_id = existing_root_id
            fingerprint_to_ca_id[root_fingerprint] = root_ca_id
            logger.info(f"Root CA '{root_cn}' already exists at {existing_root_id}, skipping import")
        else:
            root_pem = root_cert.public_bytes(Encoding.PEM).decode("utf-8")
            root_ca_id = f"root-ca-{sanitize_name(root_cn)}"

            if (self.ca_data_dir / root_ca_id).exists():
                raise ValueError(
                    f"A CA with the name '{root_cn}' already exists but has a different fingerprint. "
                    "Please resolve this conflict before importing."
                )

            root_response = self._perform_ca_import(root_cert, root_cn, root_ca_id, CAType.ROOT_CA, root_pem)
            imported_cas.append(root_response)
            fingerprint_to_ca_id[root_fingerprint] = root_ca_id
            logger.info(f"Imported root CA: {root_cn}")

        # Import intermediate CAs in order
        parent_ca_id = root_ca_id
        for int_cert in ca_certs[1:]:
            int_cn = CertificateParser._get_cn(int_cert)
            int_fingerprint = int_cert.fingerprint(hashes.SHA256()).hex().upper()

            existing_int_id = self._find_ca_by_fingerprint(int_fingerprint)
            if existing_int_id:
                parent_ca_id = existing_int_id
                fingerprint_to_ca_id[int_fingerprint] = existing_int_id
                logger.info(f"Intermediate CA '{int_cn}' already exists at {existing_int_id}, skipping import")
                continue

            int_pem = int_cert.public_bytes(Encoding.PEM).decode("utf-8")
            int_ca_id = f"{parent_ca_id}/intermediate-ca-{sanitize_name(int_cn)}"

            if (self.ca_data_dir / int_ca_id).exists():
                raise ValueError(
                    f"An intermediate CA with the name '{int_cn}' already exists under '{parent_ca_id}' "
                    "but has a different fingerprint. Please resolve this conflict before importing."
                )

            int_response = self._perform_ca_import(
                int_cert, int_cn, int_ca_id, CAType.INTERMEDIATE_CA, int_pem, parent_ca_id
            )
            imported_cas.append(int_response)
            fingerprint_to_ca_id[int_fingerprint] = int_ca_id
            parent_ca_id = int_ca_id
            logger.info(f"Imported intermediate CA: {int_cn}")

        # Import leaf certificates if cert_service is provided
        if leaf_certs and cert_service:
            for leaf_cert in leaf_certs:
                leaf_cn = CertificateParser._get_cn(leaf_cert)
                leaf_pem = leaf_cert.public_bytes(Encoding.PEM).decode("utf-8")

                # Find the issuing CA by matching the issuer subject to CA subjects
                issuing_ca_id = None
                for ca_cert in ca_certs:
                    if leaf_cert.issuer == ca_cert.subject:
                        ca_fingerprint = ca_cert.fingerprint(hashes.SHA256()).hex().upper()
                        issuing_ca_id = fingerprint_to_ca_id.get(ca_fingerprint)
                        break

                if not issuing_ca_id:
                    logger.warning(f"Could not find issuing CA for leaf certificate '{leaf_cn}', skipping")
                    continue

                # Check if certificate already exists by fingerprint
                leaf_fingerprint = leaf_cert.fingerprint(hashes.SHA256()).hex().upper()
                existing_cert_id = cert_service._find_cert_by_fingerprint(leaf_fingerprint)
                if existing_cert_id:
                    logger.info(f"Certificate '{leaf_cn}' already exists at {existing_cert_id}, skipping import")
                    continue

                # Import the leaf certificate
                from app.models.certificate import CertImportRequest

                cert_name = sanitize_name(leaf_cn)
                import_request = CertImportRequest(
                    issuing_ca_id=issuing_ca_id,
                    cert_content=leaf_pem,
                    cert_name=cert_name,
                )

                try:
                    cert_response = cert_service.import_certificate(import_request)
                    imported_cert_ids.append(cert_response.id)
                    logger.info(f"Imported certificate: {leaf_cn}")
                except ValueError as e:
                    logger.warning(f"Failed to import certificate '{leaf_cn}': {e}")

        # Build response message
        msg_parts = []
        if imported_cas:
            msg_parts.append(f"Imported {len(imported_cas)} CA(s)")
        if imported_cert_ids:
            msg_parts.append(f"Imported {len(imported_cert_ids)} certificate(s)")
        if not imported_cas and not imported_cert_ids:
            message = "All certificates in the chain already exist."
        else:
            message = "Successfully " + " and ".join(msg_parts).lower() + "."

        return ChainImportResponse(imported_cas=imported_cas, imported_certs=imported_cert_ids, message=message)

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
