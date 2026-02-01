"""CRL data models."""

from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class RevocationReason(str, Enum):
    """RFC 5280 CRL Reason Codes."""

    UNSPECIFIED = "unspecified"  # 0
    KEY_COMPROMISE = "keyCompromise"  # 1
    CA_COMPROMISE = "cACompromise"  # 2
    AFFILIATION_CHANGED = "affiliationChanged"  # 3
    SUPERSEDED = "superseded"  # 4
    CESSATION_OF_OPERATION = "cessationOfOperation"  # 5
    CERTIFICATE_HOLD = "certificateHold"  # 6
    REMOVE_FROM_CRL = "removeFromCRL"  # 8 (7 is unused)
    PRIVILEGE_WITHDRAWN = "privilegeWithdrawn"  # 9
    AA_COMPROMISE = "aACompromise"  # 10


# Map reason enum to OpenSSL reason codes
REVOCATION_REASON_CODES = {
    RevocationReason.UNSPECIFIED: "unspecified",
    RevocationReason.KEY_COMPROMISE: "keyCompromise",
    RevocationReason.CA_COMPROMISE: "CACompromise",
    RevocationReason.AFFILIATION_CHANGED: "affiliationChanged",
    RevocationReason.SUPERSEDED: "superseded",
    RevocationReason.CESSATION_OF_OPERATION: "cessationOfOperation",
    RevocationReason.CERTIFICATE_HOLD: "certificateHold",
    RevocationReason.REMOVE_FROM_CRL: "removeFromCRL",
    RevocationReason.PRIVILEGE_WITHDRAWN: "privilegeWithdrawn",
    RevocationReason.AA_COMPROMISE: "AACompromise",
}


class RevocationEntry(BaseModel):
    """Entry in the revocation list."""

    serial_number: str = Field(..., description="Certificate serial number (hex)")
    revoked_at: datetime = Field(default_factory=datetime.now)
    reason: RevocationReason = RevocationReason.UNSPECIFIED
    cert_id: Optional[str] = Field(None, description="Certificate ID if known")
    common_name: Optional[str] = Field(None, description="Certificate CN for display")


class CRLConfig(BaseModel):
    """CRL configuration stored per CA."""

    ca_id: str
    created_at: datetime = Field(default_factory=datetime.now)
    last_updated: Optional[datetime] = None
    next_update: Optional[datetime] = None
    crl_number: int = Field(default=1)
    validity_days: int = Field(default=30, description="CRL validity period")
    entries: List[RevocationEntry] = Field(default_factory=list)


class CRLResponse(BaseModel):
    """Response model for CRL operations."""

    ca_id: str
    crl_number: int
    created_at: datetime
    next_update: datetime
    revoked_count: int
    last_updated: Optional[datetime] = None


class RevokeRequest(BaseModel):
    """Request model for revoking a certificate."""

    reason: RevocationReason = RevocationReason.UNSPECIFIED
    ca_password: str = Field(..., description="CA password to sign the new CRL")


class UnrevokeRequest(BaseModel):
    """Request model for unrevoking a certificate (removing hold)."""

    ca_password: str = Field(..., description="CA password to sign the new CRL")
