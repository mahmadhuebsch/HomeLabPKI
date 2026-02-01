"""CRL API endpoints."""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.dependencies import get_crl_service, require_auth
from app.models.auth import Session
from app.models.crl import CRLResponse, RevocationEntry, RevokeRequest, UnrevokeRequest
from app.services.crl_service import CRLService

router = APIRouter(prefix="/api", tags=["CRL"])


@router.post("/certs/{cert_id:path}/revoke", response_model=CRLResponse)
def revoke_certificate(
    cert_id: str,
    request: RevokeRequest,
    session: Session = Depends(require_auth),
    crl_service: CRLService = Depends(get_crl_service),
):
    """Revoke a certificate and regenerate CRL."""
    try:
        return crl_service.revoke_certificate(
            cert_id=cert_id,
            ca_password=request.ca_password,
            reason=request.reason,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/certs/{cert_id:path}/unrevoke", response_model=CRLResponse)
def unrevoke_certificate(
    cert_id: str,
    request: UnrevokeRequest,
    session: Session = Depends(require_auth),
    crl_service: CRLService = Depends(get_crl_service),
):
    """Remove certificate hold and regenerate CRL."""
    try:
        return crl_service.unrevoke_certificate(
            cert_id=cert_id,
            ca_password=request.ca_password,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/cas/{ca_id:path}/crl", response_model=CRLResponse)
def get_crl_info(
    ca_id: str,
    session: Session = Depends(require_auth),
    crl_service: CRLService = Depends(get_crl_service),
):
    """Get CRL information for a CA."""
    try:
        crl = crl_service.get_crl_info(ca_id)
        if not crl:
            raise HTTPException(status_code=404, detail="CRL not found")
        return crl
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/cas/{ca_id:path}/crl/revoked", response_model=List[RevocationEntry])
def list_revoked_certificates(
    ca_id: str,
    session: Session = Depends(require_auth),
    crl_service: CRLService = Depends(get_crl_service),
):
    """List all revoked certificates for a CA."""
    try:
        return crl_service.list_revoked_certificates(ca_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/cas/{ca_id:path}/crl/regenerate", response_model=CRLResponse)
def regenerate_crl(
    ca_id: str,
    ca_password: str = Query(..., description="CA password to sign the CRL"),
    session: Session = Depends(require_auth),
    crl_service: CRLService = Depends(get_crl_service),
):
    """Manually regenerate CRL for a CA."""
    try:
        return crl_service.generate_crl(ca_id, ca_password)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
