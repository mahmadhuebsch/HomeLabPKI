"""CA API endpoints."""

from typing import List

from fastapi import APIRouter, Depends, HTTPException

from app.api.dependencies import get_ca_service, require_auth
from app.models.auth import Session
from app.models.ca import (
    CACreateRequest,
    CAResponse,
    IntermediateCAImportRequest,
    RootCAImportRequest,
)
from app.services.ca_service import CAService

router = APIRouter(prefix="/api/cas", tags=["CA"])


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
