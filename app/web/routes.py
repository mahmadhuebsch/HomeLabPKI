"""Web UI routes."""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.api.dependencies import get_ca_service, get_cert_service, get_config
from app.services.ca_service import CAService
from app.services.cert_service import CertificateService

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, ca_service: CAService = Depends(get_ca_service)):
    """Dashboard page."""
    try:
        root_cas = ca_service.list_root_cas()
        stats = ca_service.get_statistics()

        return templates.TemplateResponse("dashboard.html", {"request": request, "root_cas": root_cas, "stats": stats})
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=500)


@router.get("/rootcas", response_class=HTMLResponse)
async def rootca_list(request: Request, ca_service: CAService = Depends(get_ca_service)):
    """Root CA list page."""
    try:
        root_cas = ca_service.list_root_cas()

        return templates.TemplateResponse("ca/list.html", {"request": request, "root_cas": root_cas})
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=500)


@router.get("/rootcas/create", response_class=HTMLResponse)
async def rootca_create_form(request: Request, ca_service: CAService = Depends(get_ca_service)):
    """Root CA creation form."""
    try:
        config = get_config()
        defaults = config.defaults.get("root_ca", {})

        return templates.TemplateResponse(
            "ca/create.html", {"request": request, "ca_type": "root", "available_cas": [], "defaults": defaults}
        )
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=500)


@router.get("/rootcas/import", response_class=HTMLResponse)
async def rootca_import_form(request: Request, ca_service: CAService = Depends(get_ca_service)):
    """Root CA import form."""
    try:
        return templates.TemplateResponse("ca/import-root.html", {"request": request})
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=500)


@router.get("/rootcas/{ca_id:path}", response_class=HTMLResponse)
async def rootca_detail(
    request: Request,
    ca_id: str,
    ca_service: CAService = Depends(get_ca_service),
    cert_service: CertificateService = Depends(get_cert_service),
):
    """Root CA detail page."""
    try:
        from app.services.parser_service import CertificateParser
        from app.utils.file_utils import FileUtils

        ca = ca_service.get_ca(ca_id)
        certificates = cert_service.list_certificates(ca_id)

        # Get intermediate CAs under this root CA
        intermediate_cas = []
        ca_dir = ca_service.ca_data_dir / ca_id
        for intermediate_dir in FileUtils.list_directories(ca_dir):
            if intermediate_dir.name.startswith("intermediate-ca-"):
                try:
                    intermediate_id = f"{ca_id}/{intermediate_dir.name}"
                    intermediate_ca = ca_service.get_ca(intermediate_id)
                    intermediate_cas.append(intermediate_ca)
                except Exception as e:
                    pass  # Skip if failed to load

        # Read CA certificate content
        ca_cert_path = ca_service.ca_data_dir / ca_id / "ca.crt"
        ca_cert_content = FileUtils.read_file(ca_cert_path) if ca_cert_path.exists() else ""

        # Get text format
        ca_cert_text = ""
        if ca_cert_path.exists():
            try:
                ca_cert_text = CertificateParser.certificate_to_text(ca_cert_path)
            except Exception as e:
                ca_cert_text = f"Error converting to text format: {str(e)}"

        return templates.TemplateResponse(
            "ca/detail.html",
            {
                "request": request,
                "ca": ca,
                "certificates": certificates,
                "intermediate_cas": intermediate_cas,
                "ca_cert_content": ca_cert_content,
                "ca_cert_text": ca_cert_text,
            },
        )
    except ValueError as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=404)
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=500)


@router.get("/intermediates", response_class=HTMLResponse)
async def intermediate_list(request: Request, ca_service: CAService = Depends(get_ca_service)):
    """Intermediate CA list page."""
    try:
        intermediate_cas = ca_service.list_all_intermediate_cas()

        return templates.TemplateResponse(
            "intermediate/list.html", {"request": request, "intermediate_cas": intermediate_cas}
        )
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=500)


@router.get("/intermediates/create", response_class=HTMLResponse)
async def intermediate_create_form(request: Request, ca_service: CAService = Depends(get_ca_service)):
    """Intermediate CA creation form."""
    try:
        # Get all root CAs and intermediate CAs for parent selection
        available_cas = ca_service.list_root_cas()

        config = get_config()
        defaults = config.defaults.get("intermediate_ca", {})

        return templates.TemplateResponse(
            "ca/create.html",
            {"request": request, "ca_type": "intermediate", "available_cas": available_cas, "defaults": defaults},
        )
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=500)


@router.get("/intermediates/import", response_class=HTMLResponse)
async def intermediate_import_form(
    request: Request, parent_ca_id: str = "", ca_service: CAService = Depends(get_ca_service)
):
    """Intermediate CA import form."""
    try:
        # Get all root CAs for parent selection
        root_cas = ca_service.list_root_cas()

        return templates.TemplateResponse(
            "ca/import-intermediate.html",
            {"request": request, "root_cas": root_cas, "selected_parent_id": parent_ca_id},
        )
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=500)


@router.get("/intermediates/{ca_id:path}", response_class=HTMLResponse)
async def intermediate_detail(
    request: Request,
    ca_id: str,
    ca_service: CAService = Depends(get_ca_service),
    cert_service: CertificateService = Depends(get_cert_service),
):
    """Intermediate CA detail page."""
    try:
        from app.services.parser_service import CertificateParser
        from app.utils.file_utils import FileUtils

        ca = ca_service.get_ca(ca_id)
        certificates = cert_service.list_certificates(ca_id)

        # Read CA certificate content
        ca_cert_path = ca_service.ca_data_dir / ca_id / "ca.crt"
        ca_cert_content = FileUtils.read_file(ca_cert_path) if ca_cert_path.exists() else ""

        # Get text format
        ca_cert_text = ""
        if ca_cert_path.exists():
            try:
                ca_cert_text = CertificateParser.certificate_to_text(ca_cert_path)
            except Exception as e:
                ca_cert_text = f"Error converting to text format: {str(e)}"

        return templates.TemplateResponse(
            "ca/detail.html",
            {
                "request": request,
                "ca": ca,
                "certificates": certificates,
                "ca_cert_content": ca_cert_content,
                "ca_cert_text": ca_cert_text,
            },
        )
    except ValueError as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=404)
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=500)


@router.get("/certs", response_class=HTMLResponse)
async def cert_list(request: Request, cert_service: CertificateService = Depends(get_cert_service)):
    """Certificates list page."""
    try:
        certificates = cert_service.list_all_certificates()

        return templates.TemplateResponse("cert/list.html", {"request": request, "certificates": certificates})
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=500)


@router.get("/certs/create", response_class=HTMLResponse)
async def cert_create_form(request: Request, ca_id: str = "", ca_service: CAService = Depends(get_ca_service)):
    """Certificate creation form."""
    try:
        # Get all CAs for selection (both root and intermediate)
        root_cas = ca_service.list_root_cas()
        intermediate_cas = ca_service.list_all_intermediate_cas()

        # Combine all CAs
        all_cas = root_cas + intermediate_cas

        config = get_config()
        defaults = config.defaults.get("server_cert", {})

        return templates.TemplateResponse(
            "cert/create.html",
            {"request": request, "selected_ca_id": ca_id, "available_cas": all_cas, "defaults": defaults},
        )
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=500)


@router.get("/certs/sign-csr", response_class=HTMLResponse)
async def cert_sign_csr_form(request: Request, ca_id: str = "", ca_service: CAService = Depends(get_ca_service)):
    """CSR signing form."""
    try:
        # Get all CAs for selection (both root and intermediate)
        root_cas = ca_service.list_root_cas()
        intermediate_cas = ca_service.list_all_intermediate_cas()

        # Combine all CAs
        all_cas = root_cas + intermediate_cas

        config = get_config()
        defaults = config.defaults.get("server_cert", {})

        return templates.TemplateResponse(
            "cert/sign-csr.html",
            {"request": request, "selected_ca_id": ca_id, "available_cas": all_cas, "defaults": defaults},
        )
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=500)


@router.get("/certs/import", response_class=HTMLResponse)
async def cert_import_form(request: Request, ca_id: str = "", ca_service: CAService = Depends(get_ca_service)):
    """Certificate import form."""
    try:
        # Get all CAs for selection (both root and intermediate)
        root_cas = ca_service.list_root_cas()
        intermediate_cas = ca_service.list_all_intermediate_cas()

        # Combine all CAs
        all_cas = root_cas + intermediate_cas

        return templates.TemplateResponse(
            "cert/import.html", {"request": request, "selected_ca_id": ca_id, "available_cas": all_cas}
        )
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=500)


@router.get("/certs/{cert_id:path}", response_class=HTMLResponse)
async def cert_detail(request: Request, cert_id: str, cert_service: CertificateService = Depends(get_cert_service)):
    """Certificate detail page."""
    try:
        from app.services.parser_service import CertificateParser
        from app.utils.file_utils import FileUtils

        cert = cert_service.get_certificate(cert_id)

        # Read certificate content
        cert_path = cert_service.ca_data_dir / cert_id / "cert.crt"
        cert_content = FileUtils.read_file(cert_path) if cert_path.exists() else ""

        # Get text format
        cert_text = ""
        if cert_path.exists():
            try:
                cert_text = CertificateParser.certificate_to_text(cert_path)
            except Exception as e:
                cert_text = f"Error converting to text format: {str(e)}"

        return templates.TemplateResponse(
            "cert/detail.html", {"request": request, "cert": cert, "cert_content": cert_content, "cert_text": cert_text}
        )
    except ValueError as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=404)
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=500)


@router.get("/about", response_class=HTMLResponse)
async def about_page(request: Request):
    """About page."""
    try:
        config = get_config()
        return templates.TemplateResponse("about.html", {"request": request, "version": config.app.version})
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=500)
