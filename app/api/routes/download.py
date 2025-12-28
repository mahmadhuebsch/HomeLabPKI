"""Download API endpoints."""

from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import FileResponse, PlainTextResponse
from pathlib import Path

from app.services.cert_service import CertificateService
from app.api.dependencies import get_ca_data_dir, get_cert_service

router = APIRouter(prefix="/download", tags=["Downloads"])


@router.get("/ca/{ca_id:path}/cert")
def download_ca_cert(ca_id: str, ca_data_dir: Path = Depends(get_ca_data_dir)):
    """Download CA certificate (.crt)."""
    try:
        cert_path = ca_data_dir / ca_id / "ca.crt"

        if not cert_path.exists():
            raise HTTPException(status_code=404, detail="Certificate not found")

        return FileResponse(
            path=cert_path,
            media_type="application/x-pem-file",
            filename="ca.crt"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.get("/ca/{ca_id:path}/key")
def download_ca_key(ca_id: str, ca_data_dir: Path = Depends(get_ca_data_dir)):
    """Download CA private key (.key) - Handle with care!"""
    try:
        key_path = ca_data_dir / ca_id / "ca.key"

        if not key_path.exists():
            raise HTTPException(status_code=404, detail="Private key not found")

        return FileResponse(
            path=key_path,
            media_type="application/x-pem-file",
            filename="ca.key",
            headers={
                "X-Security-Warning": "This file contains a private key. Handle with care!"
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.get("/cert/{cert_id:path}/cert")
def download_cert(cert_id: str, ca_data_dir: Path = Depends(get_ca_data_dir)):
    """Download server certificate (.crt)."""
    try:
        cert_path = ca_data_dir / cert_id / "cert.crt"

        if not cert_path.exists():
            raise HTTPException(status_code=404, detail="Certificate not found")

        return FileResponse(
            path=cert_path,
            media_type="application/x-pem-file",
            filename="cert.crt"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.get("/cert/{cert_id:path}/key")
def download_cert_key(cert_id: str, ca_data_dir: Path = Depends(get_ca_data_dir)):
    """Download certificate private key (.key) - Handle with care!"""
    try:
        key_path = ca_data_dir / cert_id / "cert.key"

        if not key_path.exists():
            raise HTTPException(status_code=404, detail="Private key not found")

        return FileResponse(
            path=key_path,
            media_type="application/x-pem-file",
            filename="cert.key",
            headers={
                "X-Security-Warning": "This file contains a private key. Handle with care!"
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.get("/cert/{cert_id:path}/fullchain")
def download_cert_fullchain(
    cert_id: str,
    cert_service: CertificateService = Depends(get_cert_service)
):
    """Download full certificate chain (cert + intermediates + root)."""
    try:
        chain_pem = cert_service.build_certificate_chain(cert_id)

        return PlainTextResponse(
            content=chain_pem,
            media_type="application/x-pem-file",
            headers={
                "Content-Disposition": "attachment; filename=fullchain.pem"
            }
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")
