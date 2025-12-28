"""CA data models."""

from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, Literal
from enum import Enum


class KeyAlgorithm(str, Enum):
    """Supported key algorithms."""
    RSA = "RSA"
    ECDSA = "ECDSA"
    ED25519 = "Ed25519"


class ECDSACurve(str, Enum):
    """Supported ECDSA curves."""
    P256 = "P-256"
    P384 = "P-384"
    P521 = "P-521"


class CAType(str, Enum):
    """CA types."""
    ROOT_CA = "root_ca"
    INTERMEDIATE_CA = "intermediate_ca"


class Subject(BaseModel):
    """Certificate subject information."""
    common_name: str = Field(..., min_length=1)
    organization: Optional[str] = None
    organizational_unit: Optional[str] = None
    country: Optional[str] = Field(None, min_length=2, max_length=2)
    state: Optional[str] = None
    locality: Optional[str] = None

    class Config:
        """Pydantic config."""
        json_schema_extra = {
            "example": {
                "common_name": "My Root CA",
                "organization": "ACME Corp",
                "organizational_unit": "IT Security",
                "country": "DE",
                "state": "Hessen",
                "locality": "Frankfurt"
            }
        }


class KeyConfig(BaseModel):
    """Key configuration."""
    algorithm: KeyAlgorithm
    key_size: Optional[int] = Field(None, ge=2048)  # for RSA
    curve: Optional[ECDSACurve] = None  # for ECDSA

    class Config:
        """Pydantic config."""
        json_schema_extra = {
            "example": {
                "algorithm": "RSA",
                "key_size": 4096
            }
        }


class CAConfig(BaseModel):
    """CA configuration model."""
    type: CAType
    created_at: datetime = Field(default_factory=datetime.now)
    subject: Subject
    key_config: KeyConfig
    validity_days: int = Field(..., gt=0)
    not_before: datetime = Field(default_factory=datetime.now)
    not_after: Optional[datetime] = None
    serial_number_counter: int = Field(default=1000)
    parent_ca: Optional[str] = None  # Relative Path
    openssl_command: str = ""
    fingerprint_sha256: Optional[str] = None

    def model_post_init(self, __context):
        """Calculate not_after if not set."""
        if self.not_after is None:
            from datetime import timedelta
            self.not_after = self.not_before + timedelta(days=self.validity_days)

    class Config:
        """Pydantic config."""
        json_schema_extra = {
            "example": {
                "type": "root_ca",
                "subject": {
                    "common_name": "My Root CA",
                    "organization": "ACME Corp"
                },
                "key_config": {
                    "algorithm": "RSA",
                    "key_size": 4096
                },
                "validity_days": 3650
            }
        }


class CACreateRequest(BaseModel):
    """Request model for creating a CA."""
    type: CAType
    subject: Subject
    key_config: KeyConfig
    validity_days: int = Field(..., gt=0)
    parent_ca_id: Optional[str] = None


class RootCAImportRequest(BaseModel):
    """Request model for importing an external Root CA."""
    ca_cert_content: str  # PEM-encoded CA certificate content
    ca_name: str  # Name/identifier for the CA (will be sanitized)
    ca_key_content: Optional[str] = None  # Optional: Private key content (if available)


class IntermediateCAImportRequest(BaseModel):
    """Request model for importing an external Intermediate CA."""
    parent_ca_id: str  # Parent CA under which to import
    ca_cert_content: str  # PEM-encoded CA certificate content
    ca_name: str  # Name/identifier for the CA (will be sanitized)
    ca_key_content: Optional[str] = None  # Optional: Private key content (if available)


class CAResponse(BaseModel):
    """Response model for CA operations."""
    id: str
    path: str
    type: CAType
    subject: Subject
    not_before: datetime
    not_after: datetime
    fingerprint_sha256: Optional[str] = None
    openssl_command: str
    intermediate_count: int = 0
    cert_count: int = 0
    validity_status: str
    validity_text: str
