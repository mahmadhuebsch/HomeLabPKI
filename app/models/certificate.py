"""Certificate data models."""

from datetime import datetime
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from typing import Literal, Optional, Union

from pydantic import BaseModel, Field, field_validator, model_validator

from .ca import KeyConfig, Subject


class KeyUsageType(str, Enum):
    """Allowed Key Usage values for end-entity certificates.

    Note: keyCertSign and cRLSign are CA-only and forbidden for end-entity certs.
    """

    DIGITAL_SIGNATURE = "digitalSignature"
    NON_REPUDIATION = "nonRepudiation"
    KEY_ENCIPHERMENT = "keyEncipherment"
    DATA_ENCIPHERMENT = "dataEncipherment"
    KEY_AGREEMENT = "keyAgreement"


class ExtendedKeyUsageType(str, Enum):
    """Allowed Extended Key Usage values.

    Note: anyExtendedKeyUsage is forbidden.
    """

    SERVER_AUTH = "serverAuth"
    CLIENT_AUTH = "clientAuth"
    CODE_SIGNING = "codeSigning"
    EMAIL_PROTECTION = "emailProtection"
    TIME_STAMPING = "timeStamping"
    OCSP_SIGNING = "OCSPSigning"


# Forbidden Key Usage values for end-entity certificates (CA-only)
FORBIDDEN_KEY_USAGE = {"keyCertSign", "cRLSign"}

# Forbidden Extended Key Usage values
FORBIDDEN_EKU = {"anyExtendedKeyUsage"}

# Default extensions for TLS Server certificates
DEFAULT_KEY_USAGE = ["digitalSignature", "keyEncipherment"]
DEFAULT_EXTENDED_KEY_USAGE = ["serverAuth"]


class ServerCertConfig(BaseModel):
    """Server certificate configuration."""

    type: Literal["server_cert"] = "server_cert"
    created_at: datetime = Field(default_factory=datetime.now)
    subject: Subject
    sans: list[str] = Field(default_factory=list)
    key_config: KeyConfig
    validity_days: int
    not_before: datetime = Field(default_factory=datetime.now)
    not_after: Optional[datetime] = None
    serial_number: str  # Hex String
    issuing_ca: str  # Path to Issuing CA
    openssl_command: str = ""
    fingerprint_sha256: Optional[str] = None
    source: Literal["internal", "external"] = "internal"  # internal=we have key, external=CSR/imported
    key_usage: list[str] = Field(default_factory=lambda: DEFAULT_KEY_USAGE.copy())
    extended_key_usage: list[str] = Field(default_factory=lambda: DEFAULT_EXTENDED_KEY_USAGE.copy())

    @field_validator("sans", mode="before")
    @classmethod
    def convert_sans_to_strings(cls, v):
        """Convert IP addresses or other types in SANs to strings."""
        if v is None:
            return []
        if isinstance(v, list):
            return [str(item) for item in v]
        return v

    @field_validator("key_usage", mode="before")
    @classmethod
    def validate_key_usage(cls, v):
        """Validate key usage values and reject forbidden ones."""
        if v is None:
            return DEFAULT_KEY_USAGE.copy()
        if isinstance(v, list):
            for ku in v:
                if ku in FORBIDDEN_KEY_USAGE:
                    raise ValueError(f"Key Usage '{ku}' is forbidden for end-entity certificates (CA-only)")
            return v
        return v

    @field_validator("extended_key_usage", mode="before")
    @classmethod
    def validate_extended_key_usage(cls, v):
        """Validate extended key usage values and reject forbidden ones."""
        if v is None:
            return DEFAULT_EXTENDED_KEY_USAGE.copy()
        if isinstance(v, list):
            for eku in v:
                if eku in FORBIDDEN_EKU:
                    raise ValueError(f"Extended Key Usage '{eku}' is forbidden")
            return v
        return v

    def model_post_init(self, __context):
        """Calculate not_after if not set."""
        if self.not_after is None:
            from datetime import timedelta

            self.not_after = self.not_before + timedelta(days=self.validity_days)

    class Config:
        """Pydantic config."""

        json_schema_extra = {
            "example": {
                "subject": {"common_name": "example.com", "organization": "Example Inc"},
                "sans": ["example.com", "*.example.com", "www.example.com"],
                "key_config": {"algorithm": "RSA", "key_size": 2048},
                "validity_days": 365,
                "serial_number": "A1B2C3D4E5",
                "issuing_ca": "../..",
                "key_usage": ["digitalSignature", "keyEncipherment"],
                "extended_key_usage": ["serverAuth"],
            }
        }


class CertCreateRequest(BaseModel):
    """Request model for creating a certificate."""

    issuing_ca_id: str
    subject: Subject
    sans: list[str] = Field(default_factory=list)
    key_config: KeyConfig
    validity_days: int = Field(..., gt=0)
    issuing_ca_password: str = Field(..., description="Password for issuing CA's private key")
    key_usage: list[str] = Field(default_factory=lambda: DEFAULT_KEY_USAGE.copy())
    extended_key_usage: list[str] = Field(default_factory=lambda: DEFAULT_EXTENDED_KEY_USAGE.copy())

    @field_validator("sans", mode="before")
    @classmethod
    def convert_sans_to_strings(cls, v):
        """Convert IP addresses or other types in SANs to strings."""
        if v is None:
            return []
        if isinstance(v, list):
            return [str(item) for item in v]
        return v

    @field_validator("key_usage", mode="before")
    @classmethod
    def validate_key_usage(cls, v):
        """Validate key usage values and reject forbidden ones."""
        if v is None:
            return DEFAULT_KEY_USAGE.copy()
        if isinstance(v, list):
            for ku in v:
                if ku in FORBIDDEN_KEY_USAGE:
                    raise ValueError(f"Key Usage '{ku}' is forbidden for end-entity certificates (CA-only)")
            return v
        return v

    @field_validator("extended_key_usage", mode="before")
    @classmethod
    def validate_extended_key_usage(cls, v):
        """Validate extended key usage values and reject forbidden ones."""
        if v is None:
            return DEFAULT_EXTENDED_KEY_USAGE.copy()
        if isinstance(v, list):
            for eku in v:
                if eku in FORBIDDEN_EKU:
                    raise ValueError(f"Extended Key Usage '{eku}' is forbidden")
            return v
        return v


class CSRSignRequest(BaseModel):
    """Request model for signing a CSR."""

    issuing_ca_id: str
    csr_content: str  # PEM-encoded CSR content
    sans: list[str] = Field(default_factory=list)  # Override/add SANs
    validity_days: int = Field(..., gt=0)
    issuing_ca_password: str = Field(..., description="Password for issuing CA's private key")
    key_usage: list[str] = Field(default_factory=lambda: DEFAULT_KEY_USAGE.copy())
    extended_key_usage: list[str] = Field(default_factory=lambda: DEFAULT_EXTENDED_KEY_USAGE.copy())

    @field_validator("sans", mode="before")
    @classmethod
    def convert_sans_to_strings(cls, v):
        """Convert IP addresses or other types in SANs to strings."""
        if v is None:
            return []
        if isinstance(v, list):
            return [str(item) for item in v]
        return v

    @field_validator("key_usage", mode="before")
    @classmethod
    def validate_key_usage(cls, v):
        """Validate key usage values and reject forbidden ones."""
        if v is None:
            return DEFAULT_KEY_USAGE.copy()
        if isinstance(v, list):
            for ku in v:
                if ku in FORBIDDEN_KEY_USAGE:
                    raise ValueError(f"Key Usage '{ku}' is forbidden for end-entity certificates (CA-only)")
            return v
        return v

    @field_validator("extended_key_usage", mode="before")
    @classmethod
    def validate_extended_key_usage(cls, v):
        """Validate extended key usage values and reject forbidden ones."""
        if v is None:
            return DEFAULT_EXTENDED_KEY_USAGE.copy()
        if isinstance(v, list):
            for eku in v:
                if eku in FORBIDDEN_EKU:
                    raise ValueError(f"Extended Key Usage '{eku}' is forbidden")
            return v
        return v


class CertImportRequest(BaseModel):
    """Request model for importing an external certificate."""

    issuing_ca_id: str
    cert_content: str  # PEM-encoded certificate content
    cert_name: str  # Name/identifier for the certificate


class CertResponse(BaseModel):
    """Response model for certificate operations."""

    id: str
    path: str
    subject: Subject
    sans: list[str]
    not_before: datetime
    not_after: datetime
    serial_number: str
    fingerprint_sha256: Optional[str] = None
    issuing_ca: str
    openssl_command: str
    validity_status: str
    validity_text: str
    source: Literal["internal", "external"] = "internal"
    key_usage: list[str] = Field(default_factory=list)
    extended_key_usage: list[str] = Field(default_factory=list)

    @field_validator("sans", mode="before")
    @classmethod
    def convert_sans_to_strings(cls, v):
        """Convert IP addresses or other types in SANs to strings."""
        if v is None:
            return []
        if isinstance(v, list):
            return [str(item) for item in v]
        return v
