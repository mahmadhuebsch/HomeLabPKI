"""CSR API routes."""

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse, Response

from app.api.dependencies import get_csr_service, require_auth
from app.models.auth import Session
from app.models.certificate import (
    CSRCreateRequest,
    CSRResponse,
    CSRSignedRequest,
    CSRStatus,
)
from app.services.csr_service import CSRService

logger = logging.getLogger("homelabpki")

router = APIRouter(prefix="/api/csrs", tags=["CSRs"])


@router.post("", response_model=CSRResponse, status_code=201)
def create_csr(
    request: CSRCreateRequest,
    csr_service: CSRService = Depends(get_csr_service),
    session: Session = Depends(require_auth),
):
    """
    Create a new CSR with encrypted private key.

    Args:
        request: CSR creation request
        csr_service: CSR service dependency
        session: Authentication session

    Returns:
        CSR response

    Raises:
        HTTPException: If creation fails
    """
    try:
        return csr_service.create_csr(request)
    except ValueError as e:
        logger.error(f"CSR creation failed: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"CSR creation error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("", response_model=List[CSRResponse])
def list_csrs(
    status: Optional[CSRStatus] = Query(None, description="Filter by status"),
    csr_service: CSRService = Depends(get_csr_service),
    session: Session = Depends(require_auth),
):
    """
    List all CSRs with optional status filter.

    Args:
        status: Optional status filter
        csr_service: CSR service dependency
        session: Authentication session

    Returns:
        List of CSR responses
    """
    try:
        return csr_service.list_csrs(status_filter=status)
    except Exception as e:
        logger.error(f"CSR listing error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/{csr_id}", response_model=CSRResponse)
def get_csr(
    csr_id: str,
    csr_service: CSRService = Depends(get_csr_service),
    session: Session = Depends(require_auth),
):
    """
    Get CSR details by ID.

    Args:
        csr_id: CSR identifier
        csr_service: CSR service dependency
        session: Authentication session

    Returns:
        CSR response

    Raises:
        HTTPException: If CSR not found
    """
    try:
        return csr_service.get_csr(csr_id)
    except ValueError as e:
        logger.error(f"CSR not found: {csr_id}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"CSR retrieval error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete("/{csr_id}", status_code=204)
def delete_csr(
    csr_id: str,
    csr_service: CSRService = Depends(get_csr_service),
    session: Session = Depends(require_auth),
):
    """
    Delete CSR (soft delete - move to trash).

    Args:
        csr_id: CSR identifier
        csr_service: CSR service dependency
        session: Authentication session

    Raises:
        HTTPException: If CSR not found
    """
    try:
        csr_service.delete_csr(csr_id)
        return Response(status_code=204)
    except ValueError as e:
        logger.error(f"CSR not found: {csr_id}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"CSR deletion error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/{csr_id}/signed", response_model=CSRResponse)
def import_signed_certificate(
    csr_id: str,
    request: CSRSignedRequest,
    csr_service: CSRService = Depends(get_csr_service),
    session: Session = Depends(require_auth),
):
    """
    Import signed certificate for a CSR.

    Args:
        csr_id: CSR identifier
        request: Signed certificate import request
        csr_service: CSR service dependency
        session: Authentication session

    Returns:
        Updated CSR response

    Raises:
        HTTPException: If CSR not found or import fails
    """
    try:
        return csr_service.mark_signed(csr_id, request)
    except ValueError as e:
        logger.error(f"Signed certificate import failed: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Signed certificate import error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/{csr_id}/download/csr")
def download_csr(
    csr_id: str,
    csr_service: CSRService = Depends(get_csr_service),
    session: Session = Depends(require_auth),
):
    """
    Download CSR file.

    Args:
        csr_id: CSR identifier
        csr_service: CSR service dependency
        session: Authentication session

    Returns:
        CSR file

    Raises:
        HTTPException: If CSR not found
    """
    try:
        from pathlib import Path

        csr_dir = csr_service.csrs_dir / csr_id
        csr_file = csr_dir / "csr.pem"

        if not csr_file.exists():
            raise ValueError(f"CSR file not found: {csr_id}")

        return FileResponse(
            path=str(csr_file),
            media_type="application/x-pem-file",
            filename=f"{csr_id}.csr",
        )
    except ValueError as e:
        logger.error(f"CSR file not found: {csr_id}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"CSR download error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/{csr_id}/download/key")
def download_key(
    csr_id: str,
    csr_service: CSRService = Depends(get_csr_service),
    session: Session = Depends(require_auth),
):
    """
    Download private key file (encrypted).

    Args:
        csr_id: CSR identifier
        csr_service: CSR service dependency
        session: Authentication session

    Returns:
        Private key file

    Raises:
        HTTPException: If key file not found
    """
    try:
        from pathlib import Path

        csr_dir = csr_service.csrs_dir / csr_id
        key_file = csr_dir / "key.pem"

        if not key_file.exists():
            raise ValueError(f"Key file not found: {csr_id}")

        return FileResponse(
            path=str(key_file),
            media_type="application/x-pem-file",
            filename=f"{csr_id}.key",
        )
    except ValueError as e:
        logger.error(f"Key file not found: {csr_id}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Key download error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
