# HomeLab PKI

<div align="center">

**HomeLab PKI** - A web-based Certificate Authority (CA) management system

[![CI](https://github.com/mahmadhuebsch/HomeLabPKI/actions/workflows/ci.yml/badge.svg)](https://github.com/mahmadhuebsch/HomeLabPKI/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green.svg)](https://fastapi.tiangolo.com/)
[![OpenSSL](https://img.shields.io/badge/OpenSSL-1.1.1+-red.svg)](https://www.openssl.org/)
[![Docker](https://img.shields.io/badge/Docker-Enabled-blue.svg)](https://www.docker.com/)

[Features](#features) • [Installation](#installation) • [Configuration](#configuration) • [API](#api-documentation) • [Contributing](#contributing)

</div>

---

## Overview

HomeLab PKI is a web-based Certificate Authority management system built with FastAPI and Bootstrap 5.
It provides comprehensive tools for creating and managing Root CAs, Intermediate CAs, and server certificates through a
streamlined web interface.

Designed for development environments, testing infrastructure, internal PKI deployments, and certificate management operations.

![screenshots.gif](.github/images/screenshots.gif)

## Features

- **Root CA Management** - Create and manage self-signed Root Certificate Authorities
- **Intermediate CA Support** - Build certificate chains with Intermediate CAs
- **Server Certificates** - Issue certificates with Subject Alternative Names (SANs)
- **Certificate Extensions** - Customize Key Usage and Extended Key Usage with presets (TLS Server, TLS Client, Code Signing, etc.) or custom selection
- **Certificate Revocation (CRL)** - Full RFC 5280/2585 compliant CRL support: revoke certificates with 10 standard reasons, auto-regenerate CRL on revocation, public CRL endpoint for clients (no auth required), download in PEM or DER format, support for certificate hold (reversible)
- **Email Notifications** - Automated expiration warnings via SMTP with configurable thresholds, per-entity overrides, and background scheduling
- **CSR Management** - Create Certificate Signing Requests for external CAs (DigiCert, Let's Encrypt, etc.) with encrypted private keys stored locally
- **CSR Signing** - Sign external Certificate Signing Requests where private keys are managed externally
- **Importing** - Import and track externally-signed CAs and certificates, or import signed certificates back into CSRs
- **Multiple Certificate Formats** - View certificates in both Text (human-readable) and PEM formats
- **Modern Web Interface** - Responsive Bootstrap 5 UI with organized navigation
- **Password Protection** - Built-in authentication with configurable session expiration
- **RESTful API** - Complete API with OpenAPI documentation
- **Docker Support** - Easy deployment with Docker
- **Air-Gapped Operation** - Works without internet access (all assets bundled locally)

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Docker Deployment](#docker-deployment)
- [Project Structure](#project-structure)
- [Configuration](#configuration)
- [Authentication](#authentication)
- [Certificate Revocation Lists (CRL)](#certificate-revocation-lists-crl)
- [Email Notifications](#email-notifications)
- [API Documentation](#api-documentation)
- [Testing](#testing)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [Planned Features](#planned-features)
- [License](#license)

## Requirements

- Python 3.10 or higher
- OpenSSL 1.1.1 or higher (must be available in system PATH)

## Quick Start

```bash
# Clone the repository
git clone https://github.com/mahmadhuebsch/HomeLabPKI.git
cd HomeLabPKI

# Create and activate virtual environment
python -m venv .venv

# Activate virtual environment
# On Windows PowerShell: .\.venv\Scripts\Activate.ps1
# On Windows CMD: .venv\Scripts\activate.bat
# On Linux/Mac: source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Verify OpenSSL is available
openssl version

# Start the application
python main.py
```

1. Navigate to `http://localhost:8000`  (Default Password: "adminadmin")
2. Create a Root CA from the dashboard
3. Optionally create an Intermediate CA under the Root CA
4. Issue server certificates as needed

## Docker Deployment

You can easily run HomeLab PKI using Docker.

### Pull from GitHub Container Registry (Recommended)

```bash
# Pull the latest image
docker pull ghcr.io/mahmadhuebsch/homelabpki:latest

# Run the container
docker run -d \
  -p 8000:8000 \
  -v homelabpki_data:/app/ca-data \
  --name homelabpki \
  ghcr.io/mahmadhuebsch/homelabpki:latest
```

Available tags:
- `latest` - Latest stable release
- `v1.2.0` - Specific version
- `main` - Latest from main branch

### Build from Source

```bash
# Clone and build
git clone https://github.com/mahmadhuebsch/HomeLabPKI.git
cd HomeLabPKI
docker build -t homelabpki .

# Run the container
docker run -d \
  -p 8000:8000 \
  -v homelabpki_data:/app/ca-data \
  --name homelabpki \
  homelabpki
```

The application will be available at `http://localhost:8000`.

## Project Structure

```
HomeLabPKI/
├── app/
│   ├── api/                  # REST API endpoints
│   │   └── routes/           # API route handlers
│   ├── models/               # Pydantic models
│   ├── services/             # Business logic
│   ├── static/               # Static assets
│   │   ├── css/              # Custom CSS
│   │   ├── js/               # Custom JavaScript
│   │   └── vendor/           # Third-party libraries (Bootstrap, etc.)
│   ├── templates/            # Jinja2 HTML templates
│   ├── utils/                # Utility functions
│   └── web/                  # Web routes
├── tests/                    # Test files
├── ca-data/                  # Runtime CA storage (gitignored)
├── main.py                   # Application entry point
├── config.yaml               # Application configuration
├── requirements.txt          # Production dependencies
├── requirements-dev.txt      # Development dependencies
├── THIRD_PARTY_LICENSES.md   # Third-party library licenses
└── Dockerfile                # Docker build instructions
```

## Configuration

Edit `config.yaml` to customize application behavior:

```yaml
# Example configuration
app:
  title: "HomeLab PKI"
  debug: false

paths:
  ca_data: "./ca-data"      # Certificate storage location
  logs: "./logs"            # Log file location

auth:
  enabled: true             # Enable/disable authentication
  password_hash: null       # Auto-generated on first run (default: "adminadmin")
  session_expiry_hours: 24  # Session timeout

defaults:
  root_ca:
    validity_days: 3650     # 10 years
    key_algorithm: "RSA"
    key_size: 4096

  intermediate_ca:
    validity_days: 1825     # 5 years
    key_algorithm: "RSA"
    key_size: 4096

  server_cert:
    validity_days: 365      # 1 year
    key_algorithm: "RSA"
    key_size: 2048

security:
  warn_on_key_download: true

crl:
  base_url: null            # Set to embed CDP in certs (e.g., "http://pki.example.com:8000")
  validity_days: 30         # CRL validity period

logging:
  level: "INFO"
```

## Authentication

HomeLab PKI includes built-in password protection with session-based authentication.

### Default Credentials

- **Password**: `adminadmin` (no username required)

### Features

- **Web UI**: Cookie-based sessions with automatic redirect to login page
- **API**: Bearer token authentication for programmatic access
- **Session Management**: Configurable session expiration (default: 24 hours)
- **Password Change**: Available via Settings page or API

### API Authentication

```bash
# Get a session token
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"password": "adminadmin"}'

# Response: {"token": "uuid-token", "expires_at": "..."}

# Use the token for API requests
curl http://localhost:8000/api/cas \
  -H "Authorization: Bearer <token>"
```

### Password Recovery

If you forget your password, delete the `password_hash` line from `config.yaml` and restart the application. The password will reset to `adminadmin`.

```yaml
auth:
  enabled: true
  password_hash: null  # Delete this line or set to null to reset
  session_expiry_hours: 24
```

### Disabling Authentication

To disable authentication entirely (not recommended for networked deployments):

```yaml
auth:
  enabled: false
```

## Certificate Revocation Lists (CRL)

HomeLab PKI supports Certificate Revocation Lists per [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) and [RFC 2585](https://www.rfc-editor.org/rfc/rfc2585).

### Public CRL Endpoint

CRLs are served via a public endpoint that requires no authentication (per RFC 2585):

```
GET /download/crl/{ca_id}.crl
```

**Example:**
```bash
# Download CRL for a Root CA
curl http://localhost:8000/download/crl/root-ca-example.crl -o crl.der

# Download CRL for an Intermediate CA
curl http://localhost:8000/download/crl/root-ca-example/intermediate-ca-web.crl -o crl.der
```

### CRL Distribution Point (CDP)

HomeLab PKI can automatically embed CRL Distribution Point URLs in certificates. Configure the base URL in `config.yaml`:

```yaml
crl:
  # Base URL for CDP extension in certificates
  base_url: "http://pki.example.com:8000"
  validity_days: 30
```

When `base_url` is set, new certificates will include the CDP extension pointing to:
```
http://pki.example.com:8000/download/crl/{ca_id}.crl
```

Clients validating certificates will automatically fetch and check the CRL from this URL.

**Note:** Per RFC 2585, use HTTP (not HTTPS) for CRL distribution to avoid circular certificate validation dependencies.

### CRL Format

| Format | Content-Type | Use Case |
|--------|--------------|----------|
| DER (.crl) | `application/pkix-crl` | Standard format, used by most clients |
| PEM | `application/x-pem-file` | For OpenSSL tools and debugging |

### Revocation Reasons (RFC 5280)

- `unspecified` - No specific reason
- `keyCompromise` - Private key was compromised
- `cACompromise` - CA was compromised
- `affiliationChanged` - Subject's affiliation changed
- `superseded` - Certificate was replaced
- `cessationOfOperation` - CA or subject ceased operations
- `certificateHold` - Temporary hold (reversible)
- `removeFromCRL` - Remove from CRL (delta CRL)
- `privilegeWithdrawn` - Privilege was withdrawn
- `aACompromise` - Attribute Authority compromised

Only certificates revoked with `certificateHold` can be unrevoked.

## Email Notifications

HomeLab PKI can send email notifications when certificates, CAs, or CRLs are approaching expiration.

### Features

- **Automated Expiration Monitoring** - Periodic checks for expiring certificates
- **Configurable Thresholds** - Send notifications at multiple intervals (e.g., 90, 60, 30, 14, 7 days before expiry)
- **SMTP Support** - Send emails via any SMTP server (Gmail, Outlook, internal mail server, etc.)
- **Per-Entity Overrides** - Custom notification settings for individual CAs or certificates
- **Test Mode** - Send test emails to verify SMTP configuration
- **State Tracking** - Prevents duplicate notifications for the same threshold

### Configuration

Edit `config.yaml` to configure email notifications:

```yaml
smtp:
  enabled: true
  host: "smtp.gmail.com"
  port: 587
  encryption: starttls  # Options: none, starttls, ssl
  username: "your-email@gmail.com"
  password: "your-app-password"  # Or use environment variable
  sender_email: "pki@example.com"
  sender_name: "HomeLab PKI"

notifications:
  enabled: true
  recipients:
    - "admin@example.com"
    - "security@example.com"
  thresholds:
    - 90   # First warning at 90 days
    - 60
    - 30
    - 14
    - 7
    - 3
    - 1    # Final warning at 1 day
  check_interval_hours: 24
  check_on_startup: true
  include_ca_expiry: true
  include_cert_expiry: true
  include_crl_expiry: true
```

### Using Environment Variables for Passwords

For better security, use environment variables for SMTP credentials:

```yaml
smtp:
  password: ${SMTP_PASSWORD}
```

Then set the environment variable before starting the application:

```bash
# Linux/Mac
export SMTP_PASSWORD="your-app-password"
python main.py

# Windows PowerShell
$env:SMTP_PASSWORD="your-app-password"
python main.py
```

### Testing SMTP Configuration

Use the Settings page in the web UI to:
- Test SMTP connection
- Send a test email
- View notification status
- Manually trigger expiration checks

Or use the API:

```bash
# Test SMTP connection
curl -X POST http://localhost:8000/api/notifications/smtp/test \
  -H "Authorization: Bearer <token>"

# Send test email
curl -X POST http://localhost:8000/api/notifications/test \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"recipient": "admin@example.com"}'

# Manually trigger expiration check
curl -X POST http://localhost:8000/api/notifications/check \
  -H "Authorization: Bearer <token>"
```

### Per-Entity Notification Overrides

You can customize notification settings for individual CAs or certificates by editing their `config.yaml`:

```yaml
# ca-data/root-ca-example/config.yaml
notifications:
  enabled: true
  recipients:
    - "ca-admin@example.com"  # Additional recipients
  thresholds: [180, 90, 30]   # Custom thresholds for this CA
```

**Note:** Entity-specific recipients are **added** to global recipients. Entity-specific thresholds **replace** global thresholds.

## API Documentation

HomeLab PKI provides a complete RESTful API with automatic interactive documentation powered by FastAPI.

### Access the API Documentation

- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`
- **OpenAPI Schema**: `http://localhost:8000/openapi.json`

## Security Considerations

> **Important**: HomeLab PKI is designed for development, testing, and internal infrastructure. For production PKI, consider enterprise-grade solutions.

### Key Security Notes

- **Private Key Encryption**: All private keys are encrypted with AES-256 using a password you provide during creation. Passwords are **never stored** - you must provide the password each time you need to sign certificates with that key.
- **Password Handling**: When creating intermediate CAs or certificates, you must provide both the password for the new key and the password for the parent/issuing CA's key.
- **Authentication**: Built-in password protection is enabled by default. Change the default password immediately after installation.
- **HTTPS**: Always use HTTPS when deploying in any networked environment. Consider a reverse proxy (nginx, Caddy) for TLS termination.
- **Backup**: Regularly backup the `ca-data` directory. Note that restoring backups requires knowing the passwords for all encrypted keys.

### Best Practices

1. **Change Default Password**: Immediately change the default password via Settings after first login
2. **Offline Root CA**: Keep Root CA keys offline, use Intermediate CAs for day-to-day operations
3. **Short-Lived Certificates**: Use shorter validity periods (90-365 days) for server certificates
4. **Regular Rotation**: Rotate certificates before expiration
5. **Monitoring**: Monitor certificate expiration dates from the dashboard

For detailed security information, see [SECURITY.md](SECURITY.md).

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting a pull request.

### Development Setup

```bash
# Clone and setup
git clone https://github.com/mahmadhuebsch/HomeLabPKI.git
cd HomeLabPKI
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements-dev.txt

# Run tests
pytest tests/ -v

# Format code
black app/ tests/
isort app/ tests/
```

## Planned Features

- [x] Password support
- [x] Certificate chain import
- [x] CSR (Certificate Signing Request) management
- [x] Docker containerization
- [x] Email notifications for expiring certificates
- [x] CRL support
- [ ] ACME Protocol support
- [ ] OCSP Responder

## License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

Made with :heart: by the HomeLab PKI Contributors

</div>
