"""OpenSSL command generation and execution service."""

import logging
import shutil
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Tuple

from app.models.ca import CAConfig, KeyAlgorithm, KeyConfig, Subject
from app.models.certificate import ServerCertConfig

logger = logging.getLogger("homelabpki")


class OpenSSLService:
    """Service for OpenSSL command building and execution."""

    @staticmethod
    def _path_to_posix(path: Path) -> str:
        """
        Convert Path to absolute POSIX-style string (forward slashes) for MinGW OpenSSL compatibility.

        Args:
            path: Path object to convert

        Returns:
            Absolute path with forward slashes
        """
        # Resolve to absolute path first, then convert to POSIX
        absolute_path = path.resolve()
        return str(absolute_path).replace("\\", "/")

    def __init__(self, openssl_path: Optional[str] = None):
        """
        Initialize OpenSSL service.

        Args:
            openssl_path: Path to openssl binary. If None, uses 'openssl' from PATH.

        Note:
            OpenSSL must be installed and available in system PATH.
        """
        if openssl_path is None:
            # Use 'openssl' from PATH - no hardcoded paths
            if shutil.which("openssl") is None:
                raise RuntimeError(
                    "OpenSSL not found in PATH. Please install OpenSSL and ensure it's accessible via PATH.\n"
                    "Verify with: openssl version"
                )
            self.openssl_path = "openssl"
        else:
            self.openssl_path = openssl_path

        logger.info(f"Using OpenSSL command: {self.openssl_path}")

    def verify_key_password(self, key_path: Path, password: str) -> bool:
        """
        Verify that the provided password can decrypt the private key.

        Args:
            key_path: Path to the encrypted private key
            password: Password to verify

        Returns:
            True if password is correct, False otherwise
        """
        import shlex

        try:
            key_file_posix = self._path_to_posix(key_path)
            # Try to read the key with the password - if it works, password is correct
            cmd = f"{self.openssl_path} pkey -in {key_file_posix} -passin pass:{password} -noout"
            result = subprocess.run(
                shlex.split(cmd),
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except Exception as e:
            logger.warning(f"Password verification failed for {key_path}: {e}")
            return False

    def build_root_ca_command(self, config: CAConfig, output_dir: Path, key_password: str) -> str:
        """
        Generate OpenSSL command for Root CA creation.

        Args:
            config: CA configuration
            output_dir: Output directory for CA files
            key_password: Password for encrypting the new private key

        Returns:
            OpenSSL command string
        """
        # Use relative paths since cwd will be set to output_dir
        key_file = "ca.key"
        cert_file = "ca.crt"
        config_file = "openssl.cnf"

        # 1. Private Key Generation (encrypted with AES-256)
        key_cmd = self._build_key_gen_cmd(config.key_config, key_file, key_password)

        # 2. Self-Signed Certificate (requires password to read encrypted key)
        subject = self._build_subject_string(config.subject)
        cert_cmd = (
            f"{self.openssl_path} req -new -x509 "
            f"-days {config.validity_days} "
            f"-key {key_file} "
            f"-passin pass:{key_password} "
            f"-out {cert_file} "
            f'-subj "{subject}" '
            f"-config {config_file} "
            f"-extensions v3_ca"
        )

        return f"{key_cmd}\n{cert_cmd}"

    def build_intermediate_ca_command(
        self,
        config: CAConfig,
        output_dir: Path,
        parent_ca_dir: Path,
        key_password: str,
        parent_ca_password: str,
    ) -> str:
        """
        Generate OpenSSL command for Intermediate CA.

        Args:
            config: CA configuration
            output_dir: Output directory for CA files
            parent_ca_dir: Parent CA directory
            key_password: Password for encrypting the new private key
            parent_ca_password: Password for parent CA's private key

        Returns:
            OpenSSL command string
        """
        # Use relative paths for this CA's files
        key_file = "ca.key"
        csr_file = "ca.csr"
        cert_file = "ca.crt"
        config_file = "openssl.cnf"

        # Use relative paths for parent CA files (parent is always one level up)
        parent_cert = "../ca.crt"
        parent_key = "../ca.key"

        # 1. Private Key (encrypted with AES-256)
        key_cmd = self._build_key_gen_cmd(config.key_config, key_file, key_password)

        # 2. CSR (requires password to read new encrypted key)
        subject = self._build_subject_string(config.subject)
        csr_cmd = (
            f"{self.openssl_path} req -new "
            f"-key {key_file} "
            f"-passin pass:{key_password} "
            f"-out {csr_file} "
            f'-subj "{subject}" '
            f"-config {config_file}"
        )

        # 3. Sign with Parent (requires parent CA password)
        cert_cmd = (
            f"{self.openssl_path} x509 -req "
            f"-in {csr_file} "
            f"-CA {parent_cert} "
            f"-CAkey {parent_key} "
            f"-passin pass:{parent_ca_password} "
            f"-CAcreateserial "
            f"-out {cert_file} "
            f"-days {config.validity_days} "
            f"-sha256 "
            f"-extfile {config_file} "
            f"-extensions v3_intermediate_ca"
        )

        return f"{key_cmd}\n{csr_cmd}\n{cert_cmd}"

    def build_server_cert_command(
        self,
        config: ServerCertConfig,
        output_dir: Path,
        issuing_ca_dir: Path,
        serial_number: str,
        key_password: str,
        issuing_ca_password: str,
    ) -> str:
        """
        Generate OpenSSL command for Server Certificate.

        Args:
            config: Certificate configuration
            output_dir: Output directory for cert files
            issuing_ca_dir: Issuing CA directory
            serial_number: Serial number (hex)
            key_password: Password for encrypting the new private key
            issuing_ca_password: Password for issuing CA's private key

        Returns:
            OpenSSL command string
        """
        # Use relative paths for certificate files
        key_file = "cert.key"
        csr_file = "cert.csr"
        cert_file = "cert.crt"
        san_config = "san.cnf"

        # Use relative paths for CA files (certs are in certs/{name}/, so CA is two levels up)
        ca_cert = "../../ca.crt"
        ca_key = "../../ca.key"

        # 1. Private Key (encrypted with AES-256)
        key_cmd = self._build_key_gen_cmd(config.key_config, key_file, key_password)

        # 2. CSR (requires password to read new encrypted key)
        subject = self._build_subject_string(config.subject)
        csr_cmd = (
            f"{self.openssl_path} req -new "
            f"-key {key_file} "
            f"-passin pass:{key_password} "
            f"-out {csr_file} "
            f'-subj "{subject}" '
            f"-config {san_config}"
        )

        # 3. Certificate with SANs (requires CA password)
        cert_cmd = (
            f"{self.openssl_path} x509 -req "
            f"-in {csr_file} "
            f"-CA {ca_cert} "
            f"-CAkey {ca_key} "
            f"-passin pass:{issuing_ca_password} "
            f"-set_serial 0x{serial_number} "
            f"-out {cert_file} "
            f"-days {config.validity_days} "
            f"-sha256 "
            f"-extfile {san_config} "
            f"-extensions v3_req"
        )

        return f"{key_cmd}\n{csr_cmd}\n{cert_cmd}"

    def _build_key_gen_cmd(self, key_config: KeyConfig, output_file: str, password: str) -> str:
        """
        Generate key generation command based on algorithm with AES-256 encryption.

        Args:
            key_config: Key configuration
            output_file: Output filename (string)
            password: Password for encrypting the key

        Returns:
            Key generation command with password encryption
        """
        if key_config.algorithm == KeyAlgorithm.RSA:
            return (
                f"{self.openssl_path} genrsa -aes256 "
                f"-passout pass:{password} "
                f"-out {output_file} {key_config.key_size}"
            )

        elif key_config.algorithm == KeyAlgorithm.ECDSA:
            # Use genpkey for ECDSA with encryption (ecparam doesn't support direct encryption)
            curve_map = {"P-256": "prime256v1", "P-384": "secp384r1", "P-521": "secp521r1"}
            curve = curve_map.get(key_config.curve, "prime256v1")
            return (
                f"{self.openssl_path} genpkey -algorithm EC "
                f"-pkeyopt ec_paramgen_curve:{curve} "
                f"-aes256 -pass pass:{password} "
                f"-out {output_file}"
            )

        elif key_config.algorithm == KeyAlgorithm.ED25519:
            return (
                f"{self.openssl_path} genpkey -algorithm Ed25519 "
                f"-aes256 -pass pass:{password} "
                f"-out {output_file}"
            )

    def _build_subject_string(self, subject: Subject) -> str:
        """
        Build OpenSSL subject string.

        Args:
            subject: Subject information

        Returns:
            Subject string in OpenSSL format
        """
        parts = []

        if subject.country:
            parts.append(f"C={subject.country}")
        if subject.state:
            parts.append(f"ST={subject.state}")
        if subject.locality:
            parts.append(f"L={subject.locality}")
        if subject.organization:
            parts.append(f"O={subject.organization}")
        if subject.organizational_unit:
            parts.append(f"OU={subject.organizational_unit}")
        if subject.common_name:
            parts.append(f"CN={subject.common_name}")

        return "/" + "/".join(parts)

    def _mask_password_in_command(self, command: str) -> str:
        """
        Mask passwords in command string for logging.

        Args:
            command: Command string that may contain passwords

        Returns:
            Command string with passwords replaced by ***
        """
        import re

        masked = command
        # Mask -passout pass:XXX, -passin pass:XXX, -pass pass:XXX
        masked = re.sub(r"(-passout\s+pass:)([^\s]+)", r"\1***", masked)
        masked = re.sub(r"(-passin\s+pass:)([^\s]+)", r"\1***", masked)
        masked = re.sub(r"(-pass\s+pass:)([^\s]+)", r"\1***", masked)
        return masked

    def execute_command(self, command: str, cwd: Path) -> Tuple[bool, str, str]:
        """
        Execute OpenSSL command.

        Args:
            command: Command to execute (can be multi-line)
            cwd: Working directory

        Returns:
            Tuple of (success, stdout, stderr)
        """
        try:
            import os
            import shlex

            # Split multi-line commands
            commands = [cmd.strip() for cmd in command.split("\n") if cmd.strip()]

            all_stdout = []
            all_stderr = []

            # Create environment without OPENSSL_CONF to avoid default config path issues
            env = os.environ.copy()
            env.pop("OPENSSL_CONF", None)  # Remove OPENSSL_CONF if it exists

            for cmd in commands:
                # Log with masked password for security
                masked_cmd = self._mask_password_in_command(cmd)
                logger.info(f"Executing: {masked_cmd}")

                # Use shlex to split the command string into a list of arguments
                # This allows us to use shell=False which is safer
                args = shlex.split(cmd)

                # On Windows, shlex.split might not handle paths with backslashes correctly if not escaped
                # But since we are using POSIX paths (forward slashes) in our commands, it should be fine.
                # However, the executable path itself might be an issue if it's not just "openssl".
                # If self.openssl_path is just "openssl", it's fine.

                result = subprocess.run(args, shell=False, cwd=cwd, capture_output=True, text=True, timeout=30, env=env)

                all_stdout.append(result.stdout)
                all_stderr.append(result.stderr)

                if result.returncode != 0:
                    logger.error(f"Command failed: {result.stderr}")
                    return False, "\n".join(all_stdout), "\n".join(all_stderr)

            logger.info("Commands executed successfully")
            return True, "\n".join(all_stdout), "\n".join(all_stderr)

        except subprocess.TimeoutExpired:
            logger.error("Command timeout after 30 seconds")
            return False, "", "Command timeout after 30 seconds"
        except Exception as e:
            logger.error(f"Command execution error: {e}")
            return False, "", str(e)

    def generate_openssl_config(
        self,
        config_type: str,
        output_file: Path,
        sans: Optional[list[str]] = None,
        key_usage: Optional[list[str]] = None,
        extended_key_usage: Optional[list[str]] = None,
    ) -> None:
        """
        Generate openssl.cnf file.

        Args:
            config_type: Type of config ("root_ca", "intermediate_ca", "server_cert")
            output_file: Output file path
            sans: List of Subject Alternative Names (for server_cert)
            key_usage: List of Key Usage values (for server_cert)
            extended_key_usage: List of Extended Key Usage values (for server_cert)
        """
        if config_type == "root_ca":
            content = self._get_root_ca_config()
        elif config_type == "intermediate_ca":
            content = self._get_intermediate_ca_config()
        elif config_type == "server_cert":
            content = self._get_server_cert_config(sans or [], key_usage, extended_key_usage)
        else:
            raise ValueError(f"Unknown config type: {config_type}")

        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w") as f:
            f.write(content)

        logger.debug(f"Generated OpenSSL config: {output_file}")

    def _get_root_ca_config(self) -> str:
        """Get OpenSSL config for Root CA."""
        return """[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[ req_distinguished_name ]

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
"""

    def _get_intermediate_ca_config(self) -> str:
        """Get OpenSSL config for Intermediate CA."""
        return """[ req ]
distinguished_name = req_distinguished_name
prompt = no

[ req_distinguished_name ]

[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
"""

    def _get_server_cert_config(
        self,
        sans: list[str],
        key_usage: list[str] | None = None,
        extended_key_usage: list[str] | None = None,
    ) -> str:
        """
        Get OpenSSL config for Server Certificate.

        Args:
            sans: List of Subject Alternative Names
            key_usage: List of Key Usage values (default: digitalSignature, keyEncipherment)
            extended_key_usage: List of Extended Key Usage values (default: serverAuth)

        Returns:
            OpenSSL config content
        """
        # Use defaults if not provided
        if key_usage is None or len(key_usage) == 0:
            key_usage = ["digitalSignature", "keyEncipherment"]
        if extended_key_usage is None or len(extended_key_usage) == 0:
            extended_key_usage = ["serverAuth"]

        ku_str = ", ".join(key_usage)
        eku_str = ", ".join(extended_key_usage)
        san_entries = "\n".join([f"DNS.{i+1} = {san}" for i, san in enumerate(sans)])

        return f"""[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]

[ v3_req ]
keyUsage = critical, {ku_str}
extendedKeyUsage = {eku_str}
subjectAltName = @alt_names

[ alt_names ]
{san_entries}
"""

    @staticmethod
    def generate_serial_number() -> str:
        """
        Generate unique serial number based on timestamp.

        Returns:
            Hex serial number string
        """
        serial = hex(int(datetime.now().timestamp() * 1000000))[2:].upper()
        return serial

    def parse_csr(self, csr_content: str) -> dict:
        """
        Parse CSR and extract information.

        Args:
            csr_content: PEM-encoded CSR content

        Returns:
            Dictionary with subject, SANs, and public key info

        Raises:
            ValueError: If CSR is invalid
        """
        import shlex
        import tempfile

        try:
            # Write CSR to temp file
            with tempfile.NamedTemporaryFile(mode="w", suffix=".csr", delete=False) as f:
                f.write(csr_content)
                csr_file = Path(f.name)

            # Create minimal config to avoid "no config found" errors
            with tempfile.NamedTemporaryFile(mode="w", suffix=".cnf", delete=False) as cf:
                cf.write("[req]\ndistinguished_name = req_distinguished_name\n[req_distinguished_name]\n")
                config_file = Path(cf.name)

            try:
                # Parse CSR text
                # Use POSIX path for the file to avoid backslash issues in shlex
                csr_file_posix = self._path_to_posix(csr_file)
                config_file_posix = self._path_to_posix(config_file)
                cmd = f"{self.openssl_path} req -text -noout -in {csr_file_posix} -config {config_file_posix}"
                args = shlex.split(cmd)
                result = subprocess.run(args, shell=False, capture_output=True, text=True, timeout=10)

                if result.returncode != 0:
                    raise ValueError(f"Invalid CSR: {result.stderr}")

                csr_text = result.stdout

                # Extract subject
                subject_line = [line for line in csr_text.split("\n") if "Subject:" in line]
                subject_str = subject_line[0].split("Subject: ")[1] if subject_line else ""

                # Parse subject components
                subject_parts = {}
                for part in subject_str.split(", "):
                    if "=" in part:
                        key, value = part.split("=", 1)
                        subject_parts[key.strip()] = value.strip()

                # Extract SANs
                sans = []
                in_san_section = False
                for line in csr_text.split("\n"):
                    if "X509v3 Subject Alternative Name" in line:
                        in_san_section = True
                        continue
                    if in_san_section and "DNS:" in line:
                        # Extract all DNS entries
                        san_entries = line.strip().split(", ")
                        for entry in san_entries:
                            if entry.startswith("DNS:"):
                                sans.append(entry.replace("DNS:", ""))
                        break

                # Extract public key algorithm and size
                pub_key_info = {}
                for line in csr_text.split("\n"):
                    if "Public Key Algorithm:" in line:
                        algo = line.split(":")[1].strip()
                        pub_key_info["algorithm"] = algo
                    elif "Public-Key:" in line:
                        # Extract key size (e.g., "(2048 bit)")
                        size_match = line.split("(")[1].split(" bit")[0] if "(" in line else None
                        if size_match:
                            pub_key_info["key_size"] = int(size_match)

                return {"subject": subject_parts, "sans": sans, "public_key": pub_key_info}

            finally:
                # Clean up temp file
                if csr_file.exists():
                    csr_file.unlink()
                if config_file.exists():
                    config_file.unlink()

        except Exception as e:
            logger.error(f"CSR parsing failed: {e}")
            raise ValueError(f"Failed to parse CSR: {str(e)}")

    def sign_csr(
        self,
        csr_content: str,
        ca_cert: Path,
        ca_key: Path,
        serial_number: str,
        validity_days: int,
        sans: list[str],
        output_cert: Path,
        ca_password: str,
        key_usage: Optional[list[str]] = None,
        extended_key_usage: Optional[list[str]] = None,
    ) -> str:
        """
        Sign a CSR to generate a certificate.

        Args:
            csr_content: PEM-encoded CSR content
            ca_cert: Path to CA certificate
            ca_key: Path to CA private key
            serial_number: Serial number for the certificate
            validity_days: Validity period in days
            sans: Subject Alternative Names
            output_cert: Output certificate file path
            ca_password: Password for CA's private key
            key_usage: List of Key Usage values
            extended_key_usage: List of Extended Key Usage values

        Returns:
            OpenSSL command executed

        Raises:
            ValueError: If CSR signing fails
        """
        import tempfile

        try:
            # Write CSR to temp file
            with tempfile.NamedTemporaryFile(mode="w", suffix=".csr", delete=False) as f:
                f.write(csr_content)
                csr_file = Path(f.name)

            # Generate SAN config with extensions
            san_config = output_cert.parent / "san.cnf"
            self.generate_openssl_config("server_cert", san_config, sans, key_usage, extended_key_usage)

            try:
                # Convert paths to POSIX format
                csr_file_posix = self._path_to_posix(csr_file)
                ca_cert_posix = self._path_to_posix(ca_cert)
                ca_key_posix = self._path_to_posix(ca_key)
                output_cert_posix = self._path_to_posix(output_cert)
                san_config_posix = self._path_to_posix(san_config)

                # Build signing command (requires CA password)
                cmd = (
                    f"{self.openssl_path} x509 -req "
                    f"-in {csr_file_posix} "
                    f"-CA {ca_cert_posix} "
                    f"-CAkey {ca_key_posix} "
                    f"-passin pass:{ca_password} "
                    f"-set_serial 0x{serial_number} "
                    f"-out {output_cert_posix} "
                    f"-days {validity_days} "
                    f"-sha256 "
                    f"-extfile {san_config_posix} "
                    f"-extensions v3_req"
                )

                # Execute signing
                success, stdout, stderr = self.execute_command(cmd, output_cert.parent)

                if not success:
                    raise ValueError(f"CSR signing failed: {stderr}")

                return cmd

            finally:
                # Clean up temp CSR file
                if csr_file.exists():
                    csr_file.unlink()

        except Exception as e:
            logger.error(f"CSR signing failed: {e}")
            raise ValueError(f"Failed to sign CSR: {str(e)}")
