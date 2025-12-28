"""Main FastAPI application entry point."""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import logging

from app.api.routes import ca, cert, download
from app.web import routes as web_routes
from app.api.dependencies import get_config
from app.utils.logger import setup_logger

# Load configuration
config = get_config()

# Setup logging
setup_logger(config)
logger = logging.getLogger("yacertmanager")


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
    **YACertManager** - A modern web-based Certificate Authority management system.

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
    openapi_url="/openapi.json"
)

# Mount static files
static_dir = Path("app/static")
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Include API routers
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

    uvicorn.run(
        "main:app",
        host="localhost",
        port=8000,
        reload=config.app.debug
    )
