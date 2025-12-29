"""Certificate management service."""

import logging
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from app.models.certificate import (
    CertCreateRequest,
    CertImportRequest,
    CertResponse,
    CSRSignRequest,
    ServerCertConfig,
)
from app.services.openssl_service import OpenSSLService
from app.services.parser_service import CertificateParser
from app.services.yaml_service import YAMLService
from app.utils.file_utils import FileUtils
from app.utils.validators import sanitize_name

logger = logging.getLogger("homelabpki")


class CertificateService:
    """Service for certificate management operations."""

    def __init__(self, ca_data_dir: Path, openssl_service: OpenSSLService):
        """
        Initialize certificate service.

        Args:
            ca_data_dir: Base directory for CA data storage
            openssl_service: OpenSSL service instance
        """
        self.ca_data_dir = ca_data_dir
        self.openssl_service = openssl_service

    def create_server_certificate(self, request: CertCreateRequest) -> CertResponse:
        """
        Create a new server certificate.

        Args:
            request: Certificate creation request (must include key password and issuing CA password)

        Returns:
            Certificate response

        Raises:
            ValueError: If issuing CA not found, passwords not provided, or creation fails
        """
        # Validate key password is provided
        if not request.key_config.password:
            raise ValueError("Key password is required for certificate creation")

        # Validate issuing CA password is provided
        if not request.issuing_ca_password:
            raise ValueError("Issuing CA password is required for certificate creation")

        # Validate issuing CA exists
        issuing_ca_dir = self.ca_data_dir / request.issuing_ca_id
        if not issuing_ca_dir.exists():
            raise ValueError(f"Issuing CA not found: {request.issuing_ca_id}")

        # Sanitize domain for directory name
        domain = request.subject.common_name
        cert_id = sanitize_name(domain)
        certs_dir = issuing_ca_dir / "certs"
        cert_dir = certs_dir / cert_id

        # Check if already exists
        if cert_dir.exists():
            raise ValueError(f"Certificate already exists for: {domain}")

        try:
            # Create directory
            FileUtils.ensure_directory(cert_dir)

            # Generate serial number
            serial_number = OpenSSLService.generate_serial_number()

            # Create certificate config
            cert_config = ServerCertConfig(
                type="server_cert",
                subject=request.subject,
                sans=request.sans or [domain],
                key_config=request.key_config,
                validity_days=request.validity_days,
                created_at=datetime.now(),
                serial_number=serial_number,
                issuing_ca="../..",  # Relative path to issuing CA
                key_usage=request.key_usage,
                extended_key_usage=request.extended_key_usage,
            )

            # Generate SAN config file with extensions
            san_cnf = cert_dir / "san.cnf"
            self.openssl_service.generate_openssl_config(
                "server_cert",
                san_cnf,
                cert_config.sans,
                cert_config.key_usage,
                cert_config.extended_key_usage,
            )

            # Build OpenSSL command (pass issuing CA password for signing)
            command = self.openssl_service.build_server_cert_command(
                cert_config, cert_dir, issuing_ca_dir, serial_number, request.issuing_ca_password
            )
            # Store masked command (passwords replaced with ***)
            cert_config.openssl_command = self.openssl_service._mask_password_in_command(command)

            # Execute OpenSSL command
            success, stdout, stderr = self.openssl_service.execute_command(command, cert_dir)
            if not success:
                # Rollback: delete created directory
                FileUtils.delete_directory(cert_dir, ignore_errors=True)
                raise ValueError(f"OpenSSL command failed: {stderr}")

            # Parse created certificate
            cert_path = cert_dir / "cert.crt"
            cert_info = CertificateParser.parse_certificate(cert_path)
            cert_config.fingerprint_sha256 = cert_info["fingerprint_sha256"]
            cert_config.not_before = cert_info["not_before"]
            cert_config.not_after = cert_info["not_after"]

            # Cleanup temporary files
            csr_file = cert_dir / "cert.csr"
            if csr_file.exists():
                csr_file.unlink()
            if san_cnf.exists():
                san_cnf.unlink()

            # Save config.yaml
            config_dict = cert_config.model_dump()
            YAMLService.save_config_yaml(cert_dir / "config.yaml", config_dict)

            logger.info(f"Created server certificate for '{domain}' (Serial: {serial_number})")

            # Build response
            cert_full_id = f"{request.issuing_ca_id}/certs/{cert_id}"
            return self._build_cert_response(cert_full_id, cert_config, cert_dir)

        except Exception as e:
            # Rollback on error
            if cert_dir.exists():
                FileUtils.delete_directory(cert_dir, ignore_errors=True)
            logger.error(f"Failed to create certificate for {domain}: {e}")
            raise

    def get_certificate(self, cert_id: str) -> CertResponse:
        """
        Get certificate details by ID.

        Args:
            cert_id: Certificate identifier (e.g., "root-ca-main/certs/example-com")

        Returns:
            Certificate response

        Raises:
            ValueError: If certificate not found
        """
        cert_dir = self.ca_data_dir / cert_id
        if not cert_dir.exists():
            raise ValueError(f"Certificate not found: {cert_id}")

        # Load config
        config_path = cert_dir / "config.yaml"
        if not config_path.exists():
            raise ValueError(f"Certificate config not found: {cert_id}")

        config_data = YAMLService.load_config_yaml(config_path)
        cert_config = ServerCertConfig(**config_data)

        return self._build_cert_response(cert_id, cert_config, cert_dir)

    def list_certificates(self, ca_id: str) -> List[CertResponse]:
        """
        List all certificates under a CA.

        Args:
            ca_id: CA identifier

        Returns:
            List of certificate responses
        """
        ca_dir = self.ca_data_dir / ca_id
        if not ca_dir.exists():
            raise ValueError(f"CA not found: {ca_id}")

        certs = []
        certs_dir = ca_dir / "certs"

        if certs_dir.exists():
            for cert_dir in FileUtils.list_directories(certs_dir):
                try:
                    cert_id = f"{ca_id}/certs/{cert_dir.name}"
                    cert_response = self.get_certificate(cert_id)
                    certs.append(cert_response)
                except Exception as e:
                    logger.warning(f"Failed to load certificate {cert_dir.name}: {e}")

        return certs

    def list_all_certificates(self) -> List[CertResponse]:
        """
        List all certificates across all CAs.

        Returns:
            List of certificate responses
        """
        all_certs = []

        # Iterate through all directories to find CAs
        for root_ca_dir in FileUtils.list_directories(self.ca_data_dir):
            if root_ca_dir.name.startswith("root-ca-"):
                # Check certificates in this root CA
                all_certs.extend(self._collect_certificates_from_ca(root_ca_dir))

                # Check intermediate CAs under this root CA
                for intermediate_dir in FileUtils.list_directories(root_ca_dir):
                    if intermediate_dir.name.startswith("intermediate-ca-"):
                        all_certs.extend(self._collect_certificates_from_ca(intermediate_dir))

        return all_certs

    def _collect_certificates_from_ca(self, ca_dir: Path) -> List[CertResponse]:
        """
        Collect all certificates from a specific CA directory.

        Args:
            ca_dir: CA directory path

        Returns:
            List of certificate responses
        """
        certs = []
        certs_dir = ca_dir / "certs"

        if certs_dir.exists():
            for cert_dir in FileUtils.list_directories(certs_dir):
                try:
                    # Build relative cert_id from ca_data_dir
                    relative_ca_path = ca_dir.relative_to(self.ca_data_dir)
                    cert_id = f"{relative_ca_path}/certs/{cert_dir.name}"
                    cert_response = self.get_certificate(cert_id)
                    certs.append(cert_response)
                except Exception as e:
                    logger.warning(f"Failed to load certificate {cert_dir.name}: {e}")

        return certs

    def delete_certificate(self, cert_id: str) -> None:
        """
        Delete certificate by moving it to trash.

        Moves the certificate to a _trash folder at the same directory level
        with a timestamp suffix.

        Args:
            cert_id: Certificate identifier

        Raises:
            ValueError: If certificate not found
        """
        cert_dir = self.ca_data_dir / cert_id
        if not cert_dir.exists():
            raise ValueError(f"Certificate not found: {cert_id}")

        # Move to trash instead of permanent deletion
        trash_path = FileUtils.move_to_trash(cert_dir)

        logger.info(f"Moved certificate to trash: {cert_id} -> {trash_path}")

    def build_certificate_chain(self, cert_id: str) -> str:
        """
        Build full certificate chain (cert + intermediates + root).

        Args:
            cert_id: Certificate identifier

        Returns:
            Full chain PEM string

        Raises:
            ValueError: If certificate not found
        """
        cert_dir = self.ca_data_dir / cert_id
        if not cert_dir.exists():
            raise ValueError(f"Certificate not found: {cert_id}")

        chain_pem = []

        # 1. Certificate itself
        cert_path = cert_dir / "cert.crt"
        if cert_path.exists():
            chain_pem.append(FileUtils.read_file(cert_path))

        # 2. Load config to find issuing CA
        config_path = cert_dir / "config.yaml"
        config_data = YAMLService.load_config_yaml(config_path)

        # 3. Follow parent CA links up to root
        issuing_ca_rel = config_data.get("issuing_ca", "../..")
        current_ca = (cert_dir / issuing_ca_rel).resolve()

        while current_ca.exists():
            ca_cert_path = current_ca / "ca.crt"
            if ca_cert_path.exists():
                chain_pem.append(FileUtils.read_file(ca_cert_path))

            # Check if this CA has a parent
            ca_config_path = current_ca / "config.yaml"
            if not ca_config_path.exists():
                break

            ca_config = YAMLService.load_config_yaml(ca_config_path)
            parent_ca_rel = ca_config.get("parent_ca")

            if not parent_ca_rel:
                break  # Reached root CA

            current_ca = (current_ca / parent_ca_rel).resolve()

        # Concatenate all PEM files
        return "\n".join(chain_pem)

    def _build_cert_response(self, cert_id: str, cert_config: ServerCertConfig, cert_dir: Path) -> CertResponse:
        """
        Build certificate response from config and directory.

        Args:
            cert_id: Certificate identifier
            cert_config: Certificate configuration
            cert_dir: Certificate directory path

        Returns:
            Certificate response
        """
        # Get validity status
        status_class, status_text = CertificateParser.get_validity_status(cert_config.not_before, cert_config.not_after)

        # Get key_usage and extended_key_usage from config or parse from certificate
        key_usage = getattr(cert_config, "key_usage", [])
        extended_key_usage = getattr(cert_config, "extended_key_usage", [])

        # For imported/external certificates, parse extensions from the actual certificate
        if not key_usage or not extended_key_usage:
            cert_path = cert_dir / "cert.crt"
            if cert_path.exists():
                try:
                    cert_info = CertificateParser.parse_certificate(cert_path)
                    if not key_usage:
                        key_usage = cert_info.get("key_usage", [])
                    if not extended_key_usage:
                        extended_key_usage = cert_info.get("extended_key_usage", [])
                except Exception:
                    pass  # Keep empty lists if parsing fails

        return CertResponse(
            id=cert_id,
            path=str(cert_dir),
            subject=cert_config.subject,
            sans=cert_config.sans,
            not_before=cert_config.not_before,
            not_after=cert_config.not_after,
            serial_number=cert_config.serial_number,
            fingerprint_sha256=cert_config.fingerprint_sha256,
            issuing_ca=cert_config.issuing_ca,
            openssl_command=cert_config.openssl_command,
            validity_status=status_class,
            validity_text=status_text,
            source=cert_config.source,
            key_usage=key_usage,
            extended_key_usage=extended_key_usage,
        )

    def sign_csr(self, request: CSRSignRequest) -> CertResponse:
        """
        Sign a CSR to create a certificate.

        Args:
            request: CSR signing request (must include issuing CA password)

        Returns:
            Certificate response

        Raises:
            ValueError: If CSR is invalid, password not provided, or signing fails
        """
        # Validate issuing CA password is provided
        if not request.issuing_ca_password:
            raise ValueError("Issuing CA password is required for CSR signing")

        # Validate issuing CA exists
        issuing_ca_dir = self.ca_data_dir / request.issuing_ca_id
        if not issuing_ca_dir.exists():
            raise ValueError(f"Issuing CA not found: {request.issuing_ca_id}")

        # Parse CSR to extract information
        csr_info = self.openssl_service.parse_csr(request.csr_content)

        # Build subject from CSR
        from app.models.ca import Subject

        subject = Subject(
            common_name=csr_info["subject"].get("CN", ""),
            organization=csr_info["subject"].get("O"),
            organizational_unit=csr_info["subject"].get("OU"),
            country=csr_info["subject"].get("C"),
            state=csr_info["subject"].get("ST"),
            locality=csr_info["subject"].get("L"),
        )

        # Use SANs from request if provided, otherwise use CSR SANs
        sans = request.sans if request.sans else csr_info["sans"]
        if not sans:
            # If no SANs, use CN
            sans = [subject.common_name] if subject.common_name else []

        # Create certificate directory
        domain = subject.common_name
        cert_id = sanitize_name(domain)
        certs_dir = issuing_ca_dir / "certs"
        cert_dir = certs_dir / cert_id

        if cert_dir.exists():
            raise ValueError(f"Certificate already exists for: {domain}")

        try:
            # Create directory
            FileUtils.ensure_directory(cert_dir)

            # Generate serial number
            serial_number = OpenSSLService.generate_serial_number()

            # Determine key config from CSR public key info
            from app.models.ca import KeyConfig

            pub_key = csr_info["public_key"]

            # Map OpenSSL algorithm names to our enum values
            algo_map = {"rsaEncryption": "RSA", "id-ecPublicKey": "ECDSA", "ED25519": "Ed25519"}
            raw_algo = pub_key.get("algorithm", "rsaEncryption")
            algorithm = algo_map.get(raw_algo, "RSA")

            key_config = KeyConfig(algorithm=algorithm, key_size=pub_key.get("key_size", 2048))

            # Sign CSR
            cert_file = cert_dir / "cert.crt"
            ca_cert = issuing_ca_dir / "ca.crt"
            ca_key = issuing_ca_dir / "ca.key"

            openssl_cmd = self.openssl_service.sign_csr(
                csr_content=request.csr_content,
                ca_cert=ca_cert,
                ca_key=ca_key,
                serial_number=serial_number,
                validity_days=request.validity_days,
                sans=sans,
                output_cert=cert_file,
                ca_password=request.issuing_ca_password,
                key_usage=request.key_usage,
                extended_key_usage=request.extended_key_usage,
            )

            # Parse the generated certificate for exact dates
            cert_pem = cert_file.read_text()
            cert_info = CertificateParser.parse_certificate_pem(cert_pem)

            # Create certificate config (store masked command)
            cert_config = ServerCertConfig(
                type="server_cert",
                subject=subject,
                sans=sans,
                key_config=key_config,
                validity_days=request.validity_days,
                created_at=datetime.now(),
                not_before=cert_info["not_before"],
                not_after=cert_info["not_after"],
                serial_number=serial_number,
                issuing_ca="../..",
                openssl_command=self.openssl_service._mask_password_in_command(openssl_cmd),
                fingerprint_sha256=cert_info.get("fingerprint_sha256"),
                source="external",  # Mark as external (no private key)
                key_usage=request.key_usage,
                extended_key_usage=request.extended_key_usage,
            )

            # Save config
            config_dict = cert_config.model_dump()
            YAMLService.save_config_yaml(cert_dir / "config.yaml", config_dict)

            # Also save the original CSR for reference
            csr_file = cert_dir / "cert.csr"
            csr_file.write_text(request.csr_content)

            logger.info(f"Signed CSR for '{domain}' (Serial: {serial_number})")

            # Build certificate ID (CA path + cert name)
            full_cert_id = f"{request.issuing_ca_id}/certs/{cert_id}"
            return self._build_cert_response(full_cert_id, cert_config, cert_dir)

        except Exception as e:
            # Cleanup on failure
            if cert_dir.exists():
                FileUtils.delete_directory(cert_dir)
            raise

    def import_certificate(self, request: CertImportRequest) -> CertResponse:
        """
        Import an external certificate for tracking.

        Args:
            request: Certificate import request

        Returns:
            Certificate response

        Raises:
            ValueError: If certificate is invalid or import fails
        """
        # Validate issuing CA exists
        issuing_ca_dir = self.ca_data_dir / request.issuing_ca_id
        if not issuing_ca_dir.exists():
            raise ValueError(f"Issuing CA not found: {request.issuing_ca_id}")

        # Parse certificate
        cert_info = CertificateParser.parse_certificate_pem(request.cert_content)

        # Build subject
        from app.models.ca import Subject

        cn = cert_info["subject"].get("CN", "") or "unknown"
        subject = Subject(
            common_name=cn,
            organization=cert_info["subject"].get("O"),
            organizational_unit=cert_info["subject"].get("OU"),
            country=cert_info["subject"].get("C"),
            state=cert_info["subject"].get("ST"),
            locality=cert_info["subject"].get("L"),
        )

        # Get SANs
        sans = cert_info.get("sans", [])
        if not sans and subject.common_name:
            sans = [subject.common_name]

        # Create certificate directory
        cert_id = sanitize_name(request.cert_name)
        certs_dir = issuing_ca_dir / "certs"
        cert_dir = certs_dir / cert_id

        if cert_dir.exists():
            raise ValueError(f"Certificate already exists: {request.cert_name}")

        try:
            # Create directory
            FileUtils.ensure_directory(cert_dir)

            # Save certificate
            cert_file = cert_dir / "cert.crt"
            cert_file.write_text(request.cert_content)

            # Build key config from certificate
            from app.models.ca import KeyConfig

            key_config = KeyConfig(
                algorithm=cert_info.get("public_key_algorithm", "RSA"),
                key_size=cert_info.get("public_key_size", 2048),
            )

            # Calculate validity days
            not_before = cert_info["not_before"]
            not_after = cert_info["not_after"]
            validity_days = (not_after - not_before).days

            # Create certificate config
            cert_config = ServerCertConfig(
                type="server_cert",
                subject=subject,
                sans=sans,
                key_config=key_config,
                validity_days=validity_days,
                created_at=datetime.now(),
                not_before=not_before,
                not_after=not_after,
                serial_number=cert_info.get("serial_number", "UNKNOWN"),
                issuing_ca="../..",
                openssl_command="# Imported certificate",
                fingerprint_sha256=cert_info.get("fingerprint_sha256"),
                source="external",  # Mark as external (imported)
            )

            # Save config
            config_dict = cert_config.model_dump()
            YAMLService.save_config_yaml(cert_dir / "config.yaml", config_dict)

            logger.info(f"Imported certificate '{request.cert_name}' (Serial: {cert_config.serial_number})")

            # Build certificate ID
            full_cert_id = f"{request.issuing_ca_id}/certs/{cert_id}"
            return self._build_cert_response(full_cert_id, cert_config, cert_dir)

        except Exception as e:
            # Cleanup on failure
            if cert_dir.exists():
                FileUtils.delete_directory(cert_dir)
            raise
