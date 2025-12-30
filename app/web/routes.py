"""Web UI routes."""

from typing import Optional

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.api.dependencies import (
    get_auth_service,
    get_ca_service,
    get_cert_service,
    get_config,
    get_optional_session,
    require_auth_web,
)
from app.models.auth import Session
from app.services.auth_service import AuthService
from app.services.ca_service import CAService
from app.services.cert_service import CertificateService

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


def build_certificate_chain(ca_id: str, ca_service: CAService) -> list[dict]:
    """
    Build certificate chain from CA ID up to root.

    Returns a list of dicts with name, type, url, and id for each CA in the chain.
    The list is ordered from root to the current CA (top-down).
    Supports multiple levels of intermediate CAs.
    """
    chain = []

    # Parse the CA ID to extract the hierarchy
    # Format: root-ca-xxx or root-ca-xxx/intermediate-ca-yyy or root-ca-xxx/intermediate-ca-yyy/intermediate-ca-zzz
    parts = ca_id.split("/")

    if not parts[0].startswith("root-ca-"):
        return chain

    # Build the chain by iterating through each part
    current_id = ""
    for i, part in enumerate(parts):
        if part.startswith("root-ca-"):
            current_id = part
            ca_type = "root"
            url_prefix = "/rootcas"
        elif part.startswith("intermediate-ca-"):
            current_id = f"{current_id}/{part}" if current_id else part
            ca_type = "intermediate"
            url_prefix = "/intermediates"
        else:
            # Skip non-CA parts (like "certs")
            continue

        try:
            ca = ca_service.get_ca(current_id)
            chain.append(
                {
                    "name": ca.subject.common_name,
                    "type": ca_type,
                    "url": f"{url_prefix}/{current_id}",
                    "id": current_id,
                }
            )
        except Exception:
            chain.append(
                {
                    "name": part,
                    "type": ca_type,
                    "url": f"{url_prefix}/{current_id}",
                    "id": current_id,
                }
            )

    return chain


# =============================================================================
# Authentication Routes (no auth required)
# =============================================================================


@router.get("/login", response_class=HTMLResponse)
async def login_page(
    request: Request,
    error: str = "",
    message: str = "",
    next: str = "/",
    session: Optional[Session] = Depends(get_optional_session),
    auth_service: AuthService = Depends(get_auth_service),
):
    """Login page."""
    # If auth disabled or already logged in, redirect to dashboard
    if not auth_service.is_enabled or session:
        return RedirectResponse(url="/", status_code=302)

    return templates.TemplateResponse(
        "auth/login.html",
        {"request": request, "error": error, "message": message, "next": next},
    )


@router.post("/login", response_class=HTMLResponse)
async def login_submit(
    request: Request,
    password: str = Form(...),
    next: str = Form("/"),
    auth_service: AuthService = Depends(get_auth_service),
):
    """Process login form submission."""
    if not auth_service.is_enabled:
        return RedirectResponse(url="/", status_code=302)

    if not auth_service.verify_password(password):
        return templates.TemplateResponse(
            "auth/login.html",
            {"request": request, "error": "Invalid password", "message": "", "next": next},
            status_code=401,
        )

    # Create session
    session = auth_service.create_session(
        user_agent=request.headers.get("User-Agent"),
        ip_address=request.client.host if request.client else None,
    )

    # Validate redirect URL (must be relative path to prevent open redirect)
    redirect_url = next if next.startswith("/") and not next.startswith("//") else "/"

    # Create redirect response
    redirect = RedirectResponse(url=redirect_url, status_code=302)

    # Set session cookie (HTTP-only)
    redirect.set_cookie(
        key="session_token",
        value=session.token,
        httponly=True,
        secure=False,  # Set True in production with HTTPS
        samesite="lax",
        max_age=auth_service.settings.session_expiry_hours * 3600,
    )

    # Set CSRF cookie (readable by JavaScript for AJAX requests)
    csrf_token = auth_service.generate_csrf_token()
    redirect.set_cookie(
        key="csrf_token",
        value=csrf_token,
        httponly=False,  # Must be readable by JS
        secure=False,  # Set True in production with HTTPS
        samesite="lax",
        max_age=auth_service.settings.session_expiry_hours * 3600,
    )

    return redirect


@router.get("/logout")
async def logout_web(
    session: Optional[Session] = Depends(get_optional_session),
    auth_service: AuthService = Depends(get_auth_service),
):
    """Logout and redirect to login."""
    if session:
        auth_service.invalidate_session(session.token)

    redirect = RedirectResponse(url="/login", status_code=302)
    redirect.delete_cookie("session_token")
    redirect.delete_cookie("csrf_token")
    return redirect


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(
    request: Request,
    message: str = "",
    error: str = "",
    session: Session = Depends(require_auth_web),
    auth_service: AuthService = Depends(get_auth_service),
):
    """Settings page with password change form."""
    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "message": message,
            "error": error,
            "auth_enabled": auth_service.is_enabled,
            "csrf_token": request.cookies.get("csrf_token", ""),
        },
    )


@router.post("/settings/change-password", response_class=HTMLResponse)
async def change_password_web(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    csrf_token: str = Form(""),
    session: Session = Depends(require_auth_web),
    auth_service: AuthService = Depends(get_auth_service),
):
    """Process password change form."""
    # CSRF validation (check form field against cookie)
    cookie_csrf = request.cookies.get("csrf_token", "")

    if not auth_service.validate_csrf_token(csrf_token, cookie_csrf):
        return templates.TemplateResponse(
            "settings.html",
            {
                "request": request,
                "error": "Invalid request (CSRF)",
                "message": "",
                "auth_enabled": True,
                "csrf_token": cookie_csrf,
            },
            status_code=403,
        )

    if new_password != confirm_password:
        return templates.TemplateResponse(
            "settings.html",
            {
                "request": request,
                "error": "New passwords do not match",
                "message": "",
                "auth_enabled": True,
                "csrf_token": cookie_csrf,
            },
        )

    if len(new_password) < 8:
        return templates.TemplateResponse(
            "settings.html",
            {
                "request": request,
                "error": "Password must be at least 8 characters",
                "message": "",
                "auth_enabled": True,
                "csrf_token": cookie_csrf,
            },
        )

    if not auth_service.change_password(current_password, new_password):
        return templates.TemplateResponse(
            "settings.html",
            {
                "request": request,
                "error": "Current password is incorrect",
                "message": "",
                "auth_enabled": True,
                "csrf_token": cookie_csrf,
            },
        )

    # Password changed, redirect to login
    redirect = RedirectResponse(url="/login?message=Password+changed+successfully", status_code=302)
    redirect.delete_cookie("session_token")
    redirect.delete_cookie("csrf_token")
    return redirect


# =============================================================================
# Protected Routes (auth required)
# =============================================================================


@router.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    session: Session = Depends(require_auth_web),
    ca_service: CAService = Depends(get_ca_service),
    auth_service: AuthService = Depends(get_auth_service),
):
    """Dashboard page."""
    try:
        root_cas = ca_service.list_root_cas()
        stats = ca_service.get_statistics()

        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "root_cas": root_cas,
                "stats": stats,
                "auth_enabled": auth_service.is_enabled,
            },
        )
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=500)


@router.get("/rootcas", response_class=HTMLResponse)
async def rootca_list(
    request: Request,
    session: Session = Depends(require_auth_web),
    ca_service: CAService = Depends(get_ca_service),
    auth_service: AuthService = Depends(get_auth_service),
):
    """Root CA list page."""
    try:
        root_cas = ca_service.list_root_cas()

        return templates.TemplateResponse(
            "ca/list.html",
            {
                "request": request,
                "root_cas": root_cas,
                "auth_enabled": auth_service.is_enabled,
            },
        )
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=500)


@router.get("/rootcas/create", response_class=HTMLResponse)
async def rootca_create_form(
    request: Request,
    session: Session = Depends(require_auth_web),
    ca_service: CAService = Depends(get_ca_service),
    auth_service: AuthService = Depends(get_auth_service),
):
    """Root CA creation form."""
    try:
        config = get_config()
        defaults = config.defaults.get("root_ca", {})

        return templates.TemplateResponse(
            "ca/create.html",
            {
                "request": request,
                "ca_type": "root",
                "available_cas": [],
                "defaults": defaults,
                "auth_enabled": auth_service.is_enabled,
            },
        )
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=500)


@router.get("/rootcas/import", response_class=HTMLResponse)
async def rootca_import_form(
    request: Request,
    session: Session = Depends(require_auth_web),
    ca_service: CAService = Depends(get_ca_service),
    auth_service: AuthService = Depends(get_auth_service),
):
    """Root CA import form."""
    try:
        return templates.TemplateResponse(
            "ca/import-root.html",
            {"request": request, "auth_enabled": auth_service.is_enabled},
        )
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=500)


@router.get("/rootcas/import-chain", response_class=HTMLResponse)
async def rootca_import_chain_form(
    request: Request,
    session: Session = Depends(require_auth_web),
    ca_service: CAService = Depends(get_ca_service),
    auth_service: AuthService = Depends(get_auth_service),
):
    """Certificate chain import form."""
    try:
        return templates.TemplateResponse(
            "ca/import-chain.html",
            {"request": request, "auth_enabled": auth_service.is_enabled},
        )
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=500)


@router.get("/rootcas/{ca_id:path}", response_class=HTMLResponse)
async def rootca_detail(
    request: Request,
    ca_id: str,
    session: Session = Depends(require_auth_web),
    ca_service: CAService = Depends(get_ca_service),
    cert_service: CertificateService = Depends(get_cert_service),
    auth_service: AuthService = Depends(get_auth_service),
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
                except Exception:
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

        # Build certificate chain (for root, shows only root itself)
        cert_chain = build_certificate_chain(ca_id, ca_service)

        return templates.TemplateResponse(
            "ca/detail.html",
            {
                "request": request,
                "ca": ca,
                "certificates": certificates,
                "intermediate_cas": intermediate_cas,
                "ca_cert_content": ca_cert_content,
                "ca_cert_text": ca_cert_text,
                "cert_chain": cert_chain,
                "auth_enabled": auth_service.is_enabled,
            },
        )
    except ValueError as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=404)
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=500)


@router.get("/intermediates", response_class=HTMLResponse)
async def intermediate_list(
    request: Request,
    session: Session = Depends(require_auth_web),
    ca_service: CAService = Depends(get_ca_service),
    auth_service: AuthService = Depends(get_auth_service),
):
    """Intermediate CA list page."""
    try:
        intermediate_cas = ca_service.list_all_intermediate_cas()

        return templates.TemplateResponse(
            "intermediate/list.html",
            {
                "request": request,
                "intermediate_cas": intermediate_cas,
                "auth_enabled": auth_service.is_enabled,
            },
        )
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=500)


@router.get("/intermediates/create", response_class=HTMLResponse)
async def intermediate_create_form(
    request: Request,
    parent_ca_id: str = "",
    session: Session = Depends(require_auth_web),
    ca_service: CAService = Depends(get_ca_service),
    auth_service: AuthService = Depends(get_auth_service),
):
    """Intermediate CA creation form."""
    try:
        # Get all root CAs and intermediate CAs for parent selection
        root_cas = ca_service.list_root_cas()
        intermediate_cas = ca_service.list_all_intermediate_cas()
        available_cas = root_cas + intermediate_cas

        config = get_config()
        defaults = config.defaults.get("intermediate_ca", {})

        return templates.TemplateResponse(
            "ca/create.html",
            {
                "request": request,
                "ca_type": "intermediate",
                "available_cas": available_cas,
                "selected_parent_ca_id": parent_ca_id,
                "defaults": defaults,
                "auth_enabled": auth_service.is_enabled,
            },
        )
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=500)


@router.get("/intermediates/import", response_class=HTMLResponse)
async def intermediate_import_form(
    request: Request,
    parent_ca_id: str = "",
    session: Session = Depends(require_auth_web),
    ca_service: CAService = Depends(get_ca_service),
    auth_service: AuthService = Depends(get_auth_service),
):
    """Intermediate CA import form."""
    try:
        # Get all CAs for parent selection
        root_cas = ca_service.list_root_cas()
        intermediate_cas = ca_service.list_all_intermediate_cas()

        return templates.TemplateResponse(
            "ca/import-intermediate.html",
            {
                "request": request,
                "root_cas": root_cas,
                "intermediate_cas": intermediate_cas,
                "preselected_parent": parent_ca_id,
                "auth_enabled": auth_service.is_enabled,
            },
        )
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=500)


@router.get("/intermediates/{ca_id:path}", response_class=HTMLResponse)
async def intermediate_detail(
    request: Request,
    ca_id: str,
    session: Session = Depends(require_auth_web),
    ca_service: CAService = Depends(get_ca_service),
    cert_service: CertificateService = Depends(get_cert_service),
    auth_service: AuthService = Depends(get_auth_service),
):
    """Intermediate CA detail page."""
    try:
        from app.services.parser_service import CertificateParser
        from app.utils.file_utils import FileUtils

        ca = ca_service.get_ca(ca_id)
        certificates = cert_service.list_certificates(ca_id)

        # Get nested intermediate CAs under this intermediate CA
        intermediate_cas = []
        ca_dir = ca_service.ca_data_dir / ca_id
        for intermediate_dir in FileUtils.list_directories(ca_dir):
            if intermediate_dir.name.startswith("intermediate-ca-"):
                try:
                    intermediate_id = f"{ca_id}/{intermediate_dir.name}"
                    intermediate_ca = ca_service.get_ca(intermediate_id)
                    intermediate_cas.append(intermediate_ca)
                except Exception:
                    pass  # Skip if failed to load

        # Build certificate chain (for intermediate, shows root -> intermediate)
        cert_chain = build_certificate_chain(ca_id, ca_service)

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
                "cert_chain": cert_chain,
                "auth_enabled": auth_service.is_enabled,
            },
        )
    except ValueError as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=404)
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=500)


@router.get("/certs", response_class=HTMLResponse)
async def cert_list(
    request: Request,
    session: Session = Depends(require_auth_web),
    cert_service: CertificateService = Depends(get_cert_service),
    auth_service: AuthService = Depends(get_auth_service),
):
    """Certificates list page."""
    try:
        certificates = cert_service.list_all_certificates()

        return templates.TemplateResponse(
            "cert/list.html",
            {
                "request": request,
                "certificates": certificates,
                "auth_enabled": auth_service.is_enabled,
            },
        )
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=500)


@router.get("/certs/create", response_class=HTMLResponse)
async def cert_create_form(
    request: Request,
    ca_id: str = "",
    session: Session = Depends(require_auth_web),
    ca_service: CAService = Depends(get_ca_service),
    auth_service: AuthService = Depends(get_auth_service),
):
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
            {
                "request": request,
                "selected_ca_id": ca_id,
                "available_cas": all_cas,
                "defaults": defaults,
                "auth_enabled": auth_service.is_enabled,
            },
        )
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=500)


@router.get("/certs/sign-csr", response_class=HTMLResponse)
async def cert_sign_csr_form(
    request: Request,
    ca_id: str = "",
    session: Session = Depends(require_auth_web),
    ca_service: CAService = Depends(get_ca_service),
    auth_service: AuthService = Depends(get_auth_service),
):
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
            {
                "request": request,
                "selected_ca_id": ca_id,
                "available_cas": all_cas,
                "defaults": defaults,
                "auth_enabled": auth_service.is_enabled,
            },
        )
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=500)


@router.get("/certs/import", response_class=HTMLResponse)
async def cert_import_form(
    request: Request,
    ca_id: str = "",
    session: Session = Depends(require_auth_web),
    ca_service: CAService = Depends(get_ca_service),
    auth_service: AuthService = Depends(get_auth_service),
):
    """Certificate import form."""
    try:
        # Get all CAs for selection
        root_cas = ca_service.list_root_cas()
        intermediate_cas = ca_service.list_all_intermediate_cas()

        return templates.TemplateResponse(
            "cert/import.html",
            {
                "request": request,
                "root_cas": root_cas,
                "intermediate_cas": intermediate_cas,
                "preselected_ca": ca_id,
                "auth_enabled": auth_service.is_enabled,
            },
        )
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=500)


@router.get("/certs/{cert_id:path}", response_class=HTMLResponse)
async def cert_detail(
    request: Request,
    cert_id: str,
    session: Session = Depends(require_auth_web),
    cert_service: CertificateService = Depends(get_cert_service),
    ca_service: CAService = Depends(get_ca_service),
    auth_service: AuthService = Depends(get_auth_service),
):
    """Certificate detail page."""
    try:
        from app.services.parser_service import CertificateParser
        from app.utils.file_utils import FileUtils

        cert = cert_service.get_certificate(cert_id)

        # Build certificate chain
        # cert_id format: root-ca-xxx/certs/cert-name or
        # root-ca-xxx/intermediate-ca-yyy/certs/cert-name
        # Extract CA ID by removing /certs/cert-name
        parts = cert_id.split("/certs/")
        issuing_ca_id = parts[0] if parts else ""
        cert_chain = build_certificate_chain(issuing_ca_id, ca_service)

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
            "cert/detail.html",
            {
                "request": request,
                "cert": cert,
                "cert_content": cert_content,
                "cert_text": cert_text,
                "cert_chain": cert_chain,
                "auth_enabled": auth_service.is_enabled,
            },
        )
    except ValueError as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=404)
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=500)


@router.get("/about", response_class=HTMLResponse)
async def about_page(
    request: Request,
    session: Session = Depends(require_auth_web),
    auth_service: AuthService = Depends(get_auth_service),
):
    """About page."""
    try:
        config = get_config()
        return templates.TemplateResponse(
            "about.html",
            {
                "request": request,
                "version": config.app.version,
                "auth_enabled": auth_service.is_enabled,
            },
        )
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": str(e)}, status_code=500)
