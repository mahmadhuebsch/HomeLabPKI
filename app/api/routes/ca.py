"""CA API endpoints."""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api.dependencies import get_ca_service, get_cert_service, require_auth
from app.models.auth import Session
from app.models.ca import (
    CACreateRequest,
    CAResponse,
    ChainImportRequest,
    ChainImportResponse,
    IntermediateCAImportRequest,
    RootCAImportRequest,
)
from app.services.ca_service import CAService
from app.services.cert_service import CertificateService
from app.services.parser_service import CertificateParser


class ParseCertRequest(BaseModel):
    """Request to parse a certificate."""
    cert_content: str


class ParseCertResponse(BaseModel):
    """Response with parsed certificate info."""
    subject_cn: Optional[str] = None
    issuer_cn: Optional[str] = None
    issuer_o: Optional[str] = None
    issuer_ou: Optional[str] = None
    is_ca: bool = False
    is_self_signed: bool = False

router = APIRouter(prefix="/api/cas", tags=["CA"])


@router.post("/parse-cert", response_model=ParseCertResponse)
def parse_certificate(
    request: ParseCertRequest,
    session: Session = Depends(require_auth),
):
    """
    Parse a certificate and return subject/issuer information.

    This is used by the import forms to auto-detect the correct parent CA.
    """
    try:
        parsed = CertificateParser.parse_certificate_pem(request.cert_content)

        subject_cn = parsed.get("subject", {}).get("CN")
        issuer = parsed.get("issuer", {})
        issuer_cn = issuer.get("common_name")
        issuer_o = issuer.get("organization")
        issuer_ou = issuer.get("organizational_unit")

        # Check if self-signed (subject CN == issuer CN)
        is_self_signed = subject_cn == issuer_cn if subject_cn and issuer_cn else False

        return ParseCertResponse(
            subject_cn=subject_cn,
            issuer_cn=issuer_cn,
            issuer_o=issuer_o,
            issuer_ou=issuer_ou,
            is_ca=parsed.get("is_ca", False),
            is_self_signed=is_self_signed,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse certificate: {str(e)}")


@router.post("", response_model=CAResponse, status_code=201)
def create_ca(
    request: CACreateRequest,
    session: Session = Depends(require_auth),
    ca_service: CAService = Depends(get_ca_service),
):
    """
    Create a new CA (Root or Intermediate).

    For Root CA: Set type="root_ca"
    For Intermediate CA: Set type="intermediate_ca" and provide parent_ca_id
    """
    try:
        if request.type.value == "root_ca":
            return ca_service.create_root_ca(request)
        else:  # intermediate_ca
            if not request.parent_ca_id:
                raise HTTPException(status_code=400, detail="parent_ca_id required for intermediate CA")
            return ca_service.create_intermediate_ca(request, request.parent_ca_id)

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.post("/{parent_ca_id}/intermediates", response_model=CAResponse, status_code=201)
def create_intermediate_ca(
    parent_ca_id: str,
    request: CACreateRequest,
    session: Session = Depends(require_auth),
    ca_service: CAService = Depends(get_ca_service),
):
    """
    Create an intermediate CA under a parent CA.
    """
    try:
        return ca_service.create_intermediate_ca(request, parent_ca_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.get("", response_model=List[CAResponse])
def list_root_cas(
    session: Session = Depends(require_auth),
    ca_service: CAService = Depends(get_ca_service),
):
    """
    List all root CAs.
    """
    try:
        return ca_service.list_root_cas()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.get("/{ca_id}", response_model=CAResponse)
def get_ca(
    ca_id: str,
    session: Session = Depends(require_auth),
    ca_service: CAService = Depends(get_ca_service),
):
    """
    Get CA details by ID.
    """
    try:
        return ca_service.get_ca(ca_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.delete("/{ca_id}", status_code=204)
def delete_ca(
    ca_id: str,
    session: Session = Depends(require_auth),
    ca_service: CAService = Depends(get_ca_service),
):
    """
    Delete CA and all its contents.
    """
    try:
        ca_service.delete_ca(ca_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.get("/stats/overview")
def get_statistics(
    session: Session = Depends(require_auth),
    ca_service: CAService = Depends(get_ca_service),
):
    """
    Get CA statistics overview.
    """
    try:
        return ca_service.get_statistics()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.post("/import-root", response_model=CAResponse, status_code=201)
def import_root_ca(
    request: RootCAImportRequest,
    session: Session = Depends(require_auth),
    ca_service: CAService = Depends(get_ca_service),
):
    """
    Import an external Root CA for tracking.

    This endpoint allows importing already-signed Root CAs for tracking purposes.
    The CA certificate will be stored and optionally the private key if provided.
    """
    try:
        return ca_service.import_root_ca(request)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.post("/import-intermediate", response_model=CAResponse, status_code=201)
def import_intermediate_ca(
    request: IntermediateCAImportRequest,
    session: Session = Depends(require_auth),
    ca_service: CAService = Depends(get_ca_service),
):
    """
    Import an external Intermediate CA for tracking.

    This endpoint allows importing already-signed Intermediate CAs for tracking purposes.
    The CA certificate will be stored and optionally the private key if provided.
    """
    try:
        return ca_service.import_intermediate_ca(request)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.post("/import-chain", response_model=ChainImportResponse, status_code=201)
def import_certificate_chain(
    request: ChainImportRequest,
    session: Session = Depends(require_auth),
    ca_service: CAService = Depends(get_ca_service),
    cert_service: CertificateService = Depends(get_cert_service),
):
    """
    Import a complete certificate chain (root CA + intermediate CAs + leaf certificates).

    This endpoint validates the chain and imports all certificates.
    The chain must be complete:
    - Must contain a self-signed root CA
    - All certificates must form a valid chain (proper issuer relationships)
    - All signatures must be valid

    Both CA certificates and leaf certificates are imported.
    """
    try:
        return ca_service.import_certificate_chain(request, cert_service)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")
