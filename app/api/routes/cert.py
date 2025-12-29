"""Certificate API endpoints."""

from typing import List

from fastapi import APIRouter, Depends, HTTPException

from app.api.dependencies import get_cert_service, require_auth
from app.models.auth import Session
from app.models.certificate import (
    CertCreateRequest,
    CertImportRequest,
    CertResponse,
    CSRSignRequest,
)
from app.services.cert_service import CertificateService

router = APIRouter(prefix="/api/certs", tags=["Certificates"])


@router.post("", response_model=CertResponse, status_code=201)
def create_certificate(
    request: CertCreateRequest,
    session: Session = Depends(require_auth),
    cert_service: CertificateService = Depends(get_cert_service),
):
    """
    Create a new server certificate.
    """
    try:
        return cert_service.create_server_certificate(request)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.get("/{ca_id}/list", response_model=List[CertResponse])
def list_certificates(
    ca_id: str,
    session: Session = Depends(require_auth),
    cert_service: CertificateService = Depends(get_cert_service),
):
    """
    List all certificates under a CA.
    """
    try:
        return cert_service.list_certificates(ca_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.get("/{cert_id:path}", response_model=CertResponse)
def get_certificate(
    cert_id: str,
    session: Session = Depends(require_auth),
    cert_service: CertificateService = Depends(get_cert_service),
):
    """
    Get certificate details by ID.
    """
    try:
        return cert_service.get_certificate(cert_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.delete("/{cert_id:path}", status_code=204)
def delete_certificate(
    cert_id: str,
    session: Session = Depends(require_auth),
    cert_service: CertificateService = Depends(get_cert_service),
):
    """
    Delete certificate.
    """
    try:
        cert_service.delete_certificate(cert_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.post("/sign-csr", response_model=CertResponse, status_code=201)
def sign_csr(
    request: CSRSignRequest,
    session: Session = Depends(require_auth),
    cert_service: CertificateService = Depends(get_cert_service),
):
    """
    Sign a Certificate Signing Request (CSR).

    This endpoint allows signing external CSRs where the private key is managed externally.
    The resulting certificate will be marked as 'external' and will not have a private key file.
    """
    try:
        return cert_service.sign_csr(request)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.post("/import", response_model=CertResponse, status_code=201)
def import_certificate(
    request: CertImportRequest,
    session: Session = Depends(require_auth),
    cert_service: CertificateService = Depends(get_cert_service),
):
    """
    Import an external certificate for tracking.

    This endpoint allows importing already-signed certificates for tracking purposes.
    The certificate will be marked as 'external' and stored without a private key.
    """
    try:
        return cert_service.import_certificate(request)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")
