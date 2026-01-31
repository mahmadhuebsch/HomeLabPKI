"""Download API endpoints."""

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse, Response

from app.api.dependencies import get_ca_data_dir, get_cert_service, require_auth
from app.models.auth import Session
from app.services.cert_service import CertificateService

router = APIRouter(prefix="/download", tags=["Downloads"])


# =============================================================================
# PUBLIC CRL ENDPOINTS (RFC 2585 - No Authentication Required)
# =============================================================================
# These endpoints are intentionally public to allow clients to fetch CRLs
# without authentication. Per RFC 2585: "Authentication is not necessary
# to retrieve certificates and CRLs."
#
# Use these URLs as CRL Distribution Points (CDP) in your certificates.
# =============================================================================


@router.get("/crl/{ca_id:path}.crl", include_in_schema=True)
def download_crl_public(
    ca_id: str,
    ca_data_dir: Path = Depends(get_ca_data_dir),
):
    """
    Download CRL in DER format (public, no authentication required).

    This endpoint follows RFC 2585 requirements for CRL distribution:
    - No authentication required
    - DER format with .crl extension
    - Content-Type: application/pkix-crl

    Use this URL as the CRL Distribution Point (CDP) in your certificates.
    Example: http://your-server:8000/download/crl/root-ca-example.crl
    """
    try:
        crl_path = ca_data_dir / ca_id / "crl" / "crl.der"

        if not crl_path.exists():
            raise HTTPException(status_code=404, detail="CRL not found")

        # Read file and return with proper headers per RFC 2585
        crl_content = crl_path.read_bytes()
        return Response(
            content=crl_content,
            media_type="application/pkix-crl",
            headers={
                "Content-Disposition": f"attachment; filename={ca_id.replace('/', '-')}.crl",
                # Caching headers - CRLs should be cached but checked for updates
                "Cache-Control": "public, max-age=3600",  # 1 hour cache
            },
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.get("/ca/{ca_id:path}/cert")
def download_ca_cert(
    ca_id: str,
    session: Session = Depends(require_auth),
    ca_data_dir: Path = Depends(get_ca_data_dir),
):
    """Download CA certificate (.crt)."""
    try:
        cert_path = ca_data_dir / ca_id / "ca.crt"

        if not cert_path.exists():
            raise HTTPException(status_code=404, detail="Certificate not found")

        return FileResponse(path=cert_path, media_type="application/x-pem-file", filename="ca.crt")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.get("/ca/{ca_id:path}/key")
def download_ca_key(
    ca_id: str,
    session: Session = Depends(require_auth),
    ca_data_dir: Path = Depends(get_ca_data_dir),
):
    """Download CA private key (.key) - Handle with care!"""
    try:
        key_path = ca_data_dir / ca_id / "ca.key"

        if not key_path.exists():
            raise HTTPException(status_code=404, detail="Private key not found")

        return FileResponse(
            path=key_path,
            media_type="application/x-pem-file",
            filename="ca.key",
            headers={"X-Security-Warning": "This file contains a private key. Handle with care!"},
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.get("/cert/{cert_id:path}/cert")
def download_cert(
    cert_id: str,
    session: Session = Depends(require_auth),
    ca_data_dir: Path = Depends(get_ca_data_dir),
):
    """Download server certificate (.crt)."""
    try:
        cert_path = ca_data_dir / cert_id / "cert.crt"

        if not cert_path.exists():
            raise HTTPException(status_code=404, detail="Certificate not found")

        return FileResponse(path=cert_path, media_type="application/x-pem-file", filename="cert.crt")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.get("/cert/{cert_id:path}/key")
def download_cert_key(
    cert_id: str,
    session: Session = Depends(require_auth),
    ca_data_dir: Path = Depends(get_ca_data_dir),
):
    """Download certificate private key (.key) - Handle with care!"""
    try:
        key_path = ca_data_dir / cert_id / "cert.key"

        if not key_path.exists():
            raise HTTPException(status_code=404, detail="Private key not found")

        return FileResponse(
            path=key_path,
            media_type="application/x-pem-file",
            filename="cert.key",
            headers={"X-Security-Warning": "This file contains a private key. Handle with care!"},
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.get("/cert/{cert_id:path}/fullchain")
def download_cert_fullchain(
    cert_id: str,
    session: Session = Depends(require_auth),
    cert_service: CertificateService = Depends(get_cert_service),
):
    """Download full certificate chain (cert + intermediates + root)."""
    try:
        chain_pem = cert_service.build_certificate_chain(cert_id)

        return PlainTextResponse(
            content=chain_pem,
            media_type="application/x-pem-file",
            headers={"Content-Disposition": "attachment; filename=fullchain.pem"},
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.get("/ca/{ca_id:path}/crl")
def download_crl_pem(
    ca_id: str,
    session: Session = Depends(require_auth),
    ca_data_dir: Path = Depends(get_ca_data_dir),
):
    """Download CRL in PEM format."""
    try:
        crl_path = ca_data_dir / ca_id / "crl" / "crl.pem"

        if not crl_path.exists():
            raise HTTPException(status_code=404, detail="CRL not found")

        return FileResponse(path=crl_path, media_type="application/x-pem-file", filename="crl.pem")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.get("/ca/{ca_id:path}/crl/der")
def download_crl_der(
    ca_id: str,
    session: Session = Depends(require_auth),
    ca_data_dir: Path = Depends(get_ca_data_dir),
):
    """Download CRL in DER format."""
    try:
        crl_path = ca_data_dir / ca_id / "crl" / "crl.der"

        if not crl_path.exists():
            raise HTTPException(status_code=404, detail="CRL not found")

        return FileResponse(path=crl_path, media_type="application/pkix-crl", filename="crl.der")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")
