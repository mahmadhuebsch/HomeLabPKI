"""Main FastAPI application entry point."""

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.api.dependencies import AuthRedirect, get_config
from app.api.routes import auth, ca, cert, download
from app.utils.logger import setup_logger
from app.web import routes as web_routes

# Load configuration
config = get_config()

# Setup logging
setup_logger(config)
logger = logging.getLogger("homelabpki")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan event handler."""
    # Startup
    logger.info(f"Starting {config.app.title} v{config.app.version}")
    logger.info(f"CA data directory: {config.paths.ca_data}")

    # Ensure CA data directory exists
    ca_data_path = Path(config.paths.ca_data)
    ca_data_path.mkdir(parents=True, exist_ok=True)

    # Ensure logs directory exists
    logs_path = Path(config.paths.logs)
    logs_path.mkdir(parents=True, exist_ok=True)

    yield

    # Shutdown
    logger.info(f"Shutting down {config.app.title}")


# Create FastAPI app
app = FastAPI(
    title=config.app.title,
    version=config.app.version,
    debug=config.app.debug,
    description="""
    **HomeLab PKI** - A modern web-based Certificate Authority management system.

    Manage Root CAs, Intermediate CAs, and server certificates with ease.

    ## Features
    - Create and manage Root CAs and Intermediate CAs
    - Issue server certificates with Subject Alternative Names (SANs)
    - Support for RSA, ECDSA, and Ed25519 key algorithms
    - Download certificates, private keys, and full chains
    - View certificates in both PEM and human-readable text formats

    ## Documentation
    - **Swagger UI**: `/docs` (you are here)
    - **ReDoc**: `/redoc`
    - **OpenAPI Schema**: `/openapi.json`
    """,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Mount static files
static_dir = Path("app/static")
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.exception_handler(AuthRedirect)
async def auth_redirect_handler(request: Request, exc: AuthRedirect):
    """Redirect unauthenticated web users to login page."""
    next_url = quote(str(exc), safe="")
    return RedirectResponse(url=f"/login?next={next_url}", status_code=303)


# Include API routers
app.include_router(auth.router)
app.include_router(ca.router)
app.include_router(cert.router)
app.include_router(download.router)

# Include web UI router
app.include_router(web_routes.router)


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "version": config.app.version}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="localhost", port=8000, reload=config.app.debug)
