"""Certificate data models."""

from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, Literal
from .ca import Subject, KeyConfig


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

    def model_post_init(self, __context):
        """Calculate not_after if not set."""
        if self.not_after is None:
            from datetime import timedelta
            self.not_after = self.not_before + timedelta(days=self.validity_days)

    class Config:
        """Pydantic config."""
        json_schema_extra = {
            "example": {
                "subject": {
                    "common_name": "example.com",
                    "organization": "Example Inc"
                },
                "sans": ["example.com", "*.example.com", "www.example.com"],
                "key_config": {
                    "algorithm": "RSA",
                    "key_size": 2048
                },
                "validity_days": 365,
                "serial_number": "A1B2C3D4E5",
                "issuing_ca": "../.."
            }
        }


class CertCreateRequest(BaseModel):
    """Request model for creating a certificate."""
    issuing_ca_id: str
    subject: Subject
    sans: list[str] = Field(default_factory=list)
    key_config: KeyConfig
    validity_days: int = Field(..., gt=0)


class CSRSignRequest(BaseModel):
    """Request model for signing a CSR."""
    issuing_ca_id: str
    csr_content: str  # PEM-encoded CSR content
    sans: list[str] = Field(default_factory=list)  # Override/add SANs
    validity_days: int = Field(..., gt=0)


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
