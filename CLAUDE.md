# CLAUDE.md - Context for AI Assistant

## Project Overview

**HomeLab PKI** is a web-based Certificate Authority (CA) management system built with FastAPI and Bootstrap 5. It provides a user-friendly interface for creating and managing Root CAs, Intermediate CAs, and server certificates using OpenSSL.

**Purpose**: Simplify PKI management for development, testing, internal infrastructure, and learning purposes.

**Target Audience**: DevOps engineers and security professionals who understand PKI basics.

## Technology Stack

### Backend
- **Framework**: FastAPI 0.100+
- **Python Version**: 3.10+
- **Web Server**: Uvicorn (ASGI)
- **Certificate Engine**: OpenSSL (system PATH)
- **Crypto Library**: Python cryptography library
- **Data Storage**: YAML files (PyYAML)

### Frontend
- **UI Framework**: Bootstrap 5.3 (bundled locally)
- **Icons**: Bootstrap Icons 1.11 (bundled locally)
- **Templating**: Jinja2
- **JavaScript**: Vanilla JS (no frameworks)
- **Air-Gapped**: All assets bundled in `app/static/vendor/` - no CDN dependencies

## Architecture

### Directory Structure
```
HomeLabPKI/
├── main.py                      # FastAPI entry point
├── config.yaml                  # App configuration
├── requirements.txt             # Python dependencies
├── README.md                   # User-facing documentation
├── CLAUDE.md                   # This file - AI assistant context
├── app/
│   ├── models/                 # Pydantic models
│   │   ├── auth.py            # Auth models (Session, LoginRequest)
│   │   ├── ca.py              # CA models (CAConfig, CAResponse)
│   │   ├── certificate.py     # Certificate models
│   │   └── config.py          # Config models (AppConfig, AuthSettings)
│   ├── services/              # Business logic
│   │   ├── auth_service.py    # Authentication & session management
│   │   ├── openssl_service.py # OpenSSL command generation
│   │   ├── ca_service.py      # CA management
│   │   ├── cert_service.py    # Certificate management
│   │   ├── parser_service.py  # Certificate parsing & format conversion
│   │   └── yaml_service.py    # YAML serialization
│   ├── api/                   # RESTful API routes
│   │   ├── cas.py            # CA endpoints
│   │   ├── certs.py          # Certificate endpoints
│   │   └── downloads.py      # Download endpoints
│   ├── web/                   # Web UI routes
│   │   └── routes.py         # HTML page routes
│   ├── templates/             # Jinja2 templates
│   │   ├── base.html         # Base template with navigation
│   │   ├── dashboard.html    # Dashboard page
│   │   ├── settings.html     # Settings page (password change)
│   │   ├── auth/             # Authentication templates
│   │   │   └── login.html    # Login page
│   │   ├── ca/               # CA templates
│   │   │   ├── list.html     # Root CA list
│   │   │   ├── detail.html   # CA detail (used by both root & intermediate)
│   │   │   └── create.html   # CA creation form
│   │   ├── intermediate/     # Intermediate CA templates
│   │   │   └── list.html     # Intermediate CA list
│   │   └── cert/             # Certificate templates
│   │       ├── list.html     # Certificate list
│   │       ├── detail.html   # Certificate detail
│   │       └── create.html   # Certificate creation form
│   ├── static/               # Static assets
│   │   ├── css/
│   │   │   └── custom.css
│   │   ├── js/
│   │   │   └── app.js
│   │   └── vendor/           # Third-party libraries (bundled for air-gapped operation)
│   │       ├── bootstrap-5.3.0/
│   │       │   ├── css/bootstrap.min.css
│   │       │   └── js/bootstrap.bundle.min.js
│   │       └── bootstrap-icons-1.11.0/
│   │           └── font/
│   │               ├── bootstrap-icons.min.css
│   │               └── fonts/
│   │                   ├── bootstrap-icons.woff
│   │                   └── bootstrap-icons.woff2
│   └── utils/                # Utility functions
│       ├── validators.py     # Input validation
│       └── file_utils.py     # File operations
└── ca-data/                  # Runtime certificate storage
    ├── root-ca-*/            # Root CA directories
    │   ├── ca.crt           # CA certificate
    │   ├── ca.key           # CA private key
    │   ├── config.yaml      # CA configuration
    │   ├── serial           # Serial number tracker
    │   ├── openssl.cnf      # OpenSSL config
    │   ├── certs/           # Issued certificates
    │   └── intermediate-ca-*/ # Intermediate CAs
    └── ...
```

## Key Components

### 1. OpenSSL Service (`app/services/openssl_service.py`)
- Generates OpenSSL commands for CA and certificate creation
- Executes OpenSSL via subprocess
- **CRITICAL**: Uses `openssl` from system PATH, not hardcoded paths
- Converts Windows paths to POSIX format for OpenSSL compatibility
- Key methods:
  - `build_root_ca_command()` - Root CA creation
  - `build_intermediate_ca_command()` - Intermediate CA creation
  - `build_server_cert_command()` - Server certificate creation
  - `execute_command()` - Execute OpenSSL commands
  - `_path_to_posix()` - Convert paths using `path.resolve()` for absolute paths

### 2. CA Service (`app/services/ca_service.py`)
- Manages Root and Intermediate CAs
- Key methods:
  - `create_root_ca()` - Create new Root CA
  - `create_intermediate_ca()` - Create Intermediate CA under parent
  - `list_root_cas()` - List all Root CAs
  - `list_all_intermediate_cas()` - List all Intermediate CAs across all roots
  - `get_ca()` - Get CA by ID
  - `delete_ca()` - Move CA to trash (soft delete)
- CA IDs:
  - Root: `root-ca-{sanitized_cn}`
  - Intermediate: `{parent_id}/intermediate-ca-{sanitized_cn}`

### 3. Certificate Service (`app/services/cert_service.py`)
- Manages server certificates
- Key methods:
  - `create_server_certificate()` - Issue new certificate
  - `get_certificate()` - Get certificate by ID
  - `list_certificates()` - List certificates for a CA
  - `list_all_certificates()` - List all certificates across all CAs
  - `delete_certificate()` - Move certificate to trash (soft delete)
  - `build_certificate_chain()` - Build full chain
- Certificate IDs: `{ca_id}/certs/{sanitized_domain}`

### 4. Parser Service (`app/services/parser_service.py`)
- Parses X.509 certificates using cryptography library
- Converts certificates to text format using OpenSSL
- Extracts Key Usage and Extended Key Usage extensions
- Key methods:
  - `parse_certificate()` - Extract certificate data including extensions
  - `certificate_to_text()` - Convert to human-readable text format
  - `get_validity_status()` - Check expiration status
  - `verify_key_pair()` - Verify cert/key match
  - `_extract_key_usage()` - Extract Key Usage extension values
  - `_extract_extended_key_usage()` - Extract Extended Key Usage values

### 5. YAML Service (`app/services/yaml_service.py`)
- Handles YAML serialization/deserialization
- **IMPORTANT**: Custom Enum handling to prevent serialization errors
- Converts Enum objects to their `.value` property before saving
- Key methods:
  - `save_config_yaml()` - Save config with Enum handling
  - `load_config_yaml()` - Load config

## Recent Features & Changes

### Navigation Restructure
- Separated navigation into four sections:
  1. **Dashboard** - Overview and statistics
  2. **Root CAs** - List and manage root CAs (route: `/rootcas`)
  3. **Intermediates** - List and manage intermediate CAs (route: `/intermediates`)
  4. **Certificates** - List and manage all certificates (route: `/certs`)

### Certificate Format Display
- **Text Format**: Human-readable decoded certificate (default tab)
  - Shows version, serial, issuer, subject, validity, public key, extensions
  - Generated using: `openssl x509 -in cert.crt -text -noout`
- **PEM Format**: Base64-encoded certificate
- Both formats available via tabbed interface with copy functionality
- Applied to: Root CAs, Intermediate CAs, and Certificates

### Live Command Preview
- Real-time OpenSSL command preview while creating CAs/certificates
- JavaScript mirrors Python command generation logic
- Updates as user types in form fields
- Sticky sidebar on creation forms

### Key Algorithms Supported
- **RSA**: 2048, 4096, 8192 bit
- **ECDSA**: P-256, P-384, P-521 curves
- **Ed25519**: Modern elliptic curve

### Trash Bin (Soft Delete)
- Deleted CAs and certificates are moved to `_trash` folder instead of permanent deletion
- Trash folder is created at the same directory level as the deleted item
- Deleted items are renamed with timestamp suffix to avoid conflicts (e.g., `root-ca-example_20241228_143052`)
- `_trash` folders are automatically excluded from all listings
- No UI for restore - manual file recovery if needed
- No auto-cleanup - items remain in trash indefinitely

### Certificate Extensions (Key Usage / Extended Key Usage)
- Users can select Key Usage and Extended Key Usage when creating server certificates
- Extension presets available for common use cases:
  - **TLS Server**: digitalSignature, keyEncipherment + serverAuth (default)
  - **TLS Client**: digitalSignature + clientAuth
  - **TLS Server + Client**: digitalSignature, keyEncipherment + serverAuth, clientAuth
  - **Code Signing**: digitalSignature + codeSigning
  - **Email (S/MIME)**: digitalSignature, keyEncipherment + emailProtection
  - **Timestamping**: digitalSignature + timeStamping
  - **OCSP Signing**: digitalSignature + OCSPSigning
  - **Custom**: User selects individual Key Usage and Extended Key Usage values
- Forbidden extensions for end-entity certificates (CA-only):
  - `keyCertSign` - only for CA certificates
  - `cRLSign` - only for CA certificates
  - `anyExtendedKeyUsage` - not allowed at all
- Extensions are displayed on certificate and CA detail pages as badges
- Extensions are parsed from imported certificates for display
- Applies to: Certificate creation form and CSR signing form

### Private Key Password Handling
- **All private keys are encrypted** with AES-256 using a user-provided password
- **Passwords are NEVER stored** in config files or anywhere else
- `config.yaml` stores only `encrypted: bool` flag to indicate key encryption status
- Password required at runtime for:
  - Creating intermediate CAs (parent CA password required to sign)
  - Creating certificates (issuing CA password required to sign)
  - Any future operations that need to decrypt the private key
- Request models use flat structure for passwords:
  - `CACreateRequest`: `key_password` (for new key), `parent_ca_password` (for signing)
  - `CertCreateRequest`: `key_password` (for new key), `issuing_ca_password` (for signing)
- Key methods:
  - `CertificateParser.is_key_encrypted(key_path)` - Detects encryption from PEM header
  - `OpenSSLService.verify_key_password(key_path, password)` - Verifies password can decrypt key
- Migration script: `scripts/migrate_remove_passwords.py` for existing installations

## Important Implementation Details

### Path Handling
- All paths use `pathlib.Path` for cross-platform compatibility
- OpenSSL requires POSIX paths, even on Windows
- `_path_to_posix()` in OpenSSLService:
  - Uses `path.resolve()` to get absolute path first
  - Converts backslashes to forward slashes
  - Critical for nested directory operations

### Enum Serialization
- Pydantic Enums (CAType, KeyAlgorithm, etc.) must be converted to `.value` before YAML serialization
- Custom YAML representer registered for Enum objects
- Prevents: `"could not determine a constructor for the tag 'tag:yaml.org,2002:python/object/apply:app.models.ca.CAType'"`

### Certificate ID Format
- Root CA: `root-ca-example-com`
- Intermediate CA: `root-ca-example-com/intermediate-ca-subdomain`
- Certificate: `root-ca-example-com/certs/example-com`
- IDs use sanitized names (lowercase, hyphens instead of spaces/dots)

### File Structure
Each CA directory contains:
- `ca.crt` - Public certificate
- `ca.key` - Private key (AES-256 encrypted)
- `config.yaml` - CA configuration (contains `encrypted: true` flag, NO password stored)
- `serial` - Serial number tracker
- `openssl.cnf` - OpenSSL configuration
- `certs/` - Issued certificates subdirectory
- `intermediate-ca-*/` - Intermediate CA subdirectories
- `_trash/` - Trash folder for deleted items (excluded from listings)

Each certificate directory contains:
- `cert.crt` - Public certificate
- `cert.key` - Private key (AES-256 encrypted)
- `config.yaml` - Certificate configuration (contains `encrypted: true` flag, NO password stored)

### Trash Structure
```
ca-data/
├── _trash/                              # Trash for deleted root CAs
│   └── root-ca-example_20241228_143052/
├── root-ca-example/
│   ├── _trash/                          # Trash for deleted intermediate CAs
│   │   └── intermediate-ca-sub_20241228_143052/
│   └── certs/
│       └── _trash/                      # Trash for deleted certificates
│           └── www-example_20241228_143052/
```

## Common Tasks

### Adding New Functionality
1. **Update Models** (`app/models/`) - Define Pydantic models
2. **Add Service Logic** (`app/services/`) - Business logic
3. **Create API Endpoints** (`app/api/`) - RESTful API
4. **Create Web Routes** (`app/web/routes.py`) - HTML pages
5. **Create Templates** (`app/templates/`) - Jinja2 HTML
6. **Update README.md** - Document new features
7. **Update CLAUDE.md** - Update this file with context

### Reading Certificates
- Use `FileUtils.read_file()` for PEM content
- Use `CertificateParser.certificate_to_text()` for text format
- Both methods used in detail routes for dual display

### Adding New Routes
Web routes in `app/web/routes.py`:
- Use dependency injection: `Depends(get_ca_service)`, `Depends(get_cert_service)`
- Read certificate content from `service.ca_data_dir / ca_id / "ca.crt"`
- Pass data to templates via `templates.TemplateResponse()`

### Template Updates
- Base template: `app/templates/base.html` - Navigation and layout
- Use Bootstrap 5 classes for styling
- Use Bootstrap Icons for icons
- Jinja2 syntax for variables: `{{ variable }}`
- Example of format tabs (see `ca/detail.html` or `cert/detail.html`)

## Authentication

### Overview
HomeLab PKI includes password-based authentication to protect access to the application.

### Key Features
- **Password-only authentication** (no username required)
- **Session-based**: In-memory session storage (sessions lost on restart)
- **Dual authentication methods**:
  - API: Bearer token in `Authorization` header
  - Web UI: HTTP-only session cookies
- **CSRF protection**: Double-submit cookie pattern for web forms
- **Configurable session expiry**: Default 24 hours

### Configuration (`config.yaml`)
```yaml
auth:
  enabled: true
  password_hash: null  # Auto-set on first run (default: "adminadmin")
  session_expiry_hours: 24
```

### API Endpoints
- `POST /api/auth/login` - Authenticate and get session token
- `POST /api/auth/logout` - Invalidate session
- `POST /api/auth/change-password` - Change password
- `GET /api/auth/session` - Check session status

### Web Routes
- `GET /login` - Login page
- `POST /login` - Login form submission
- `GET /logout` - Logout and redirect
- `GET /settings` - Settings page with password change

### Password Recovery
If you forget your password:
1. Stop the application
2. Edit `config.yaml`
3. Set `password_hash: null`
4. Restart the application
5. Login with default password: `adminadmin`
6. Immediately change your password

### Auth Service (`app/services/auth_service.py`)
- Password hashing using bcrypt (12 rounds)
- Session creation/validation/invalidation
- CSRF token generation and validation
- Key methods:
  - `hash_password()` - Hash password with bcrypt
  - `verify_password()` - Verify password against hash
  - `create_session()` - Create new session
  - `validate_session()` - Validate session token
  - `change_password()` - Change password and invalidate sessions

### Dependencies (`app/api/dependencies.py`)
- `get_auth_service()` - Singleton auth service
- `get_optional_session()` - Get session from Bearer token or cookie
- `require_auth()` - Require valid session (returns 401 if not authenticated)

## Known Issues & Technical Debt

### Security Considerations
- **Single Password**: Application uses single password (no multi-user)
- **Encrypted Keys**: Private keys are encrypted with AES-256, but passwords must be remembered (not stored)
- **For Development**: Not recommended for production PKI
- **In-memory Sessions**: Sessions lost on application restart

### Limitations
- No certificate revocation lists (CRL)
- No OCSP responder
- No HSM support
- No multi-user support

## Development Guidelines

### Code Style
- Follow existing patterns in the codebase
- Use type hints for function parameters and returns
- Document functions with docstrings
- Keep functions focused and single-purpose

### Error Handling
- Use try/except in routes with appropriate status codes
- Return 404 for not found, 500 for server errors
- Log errors using `logger.error()`
- Provide user-friendly error messages

### Testing

**Test Framework:** pytest with coverage reporting

**Test Structure:**
```
tests/
├── conftest.py              # Shared fixtures and configuration
├── test_auth.py             # Authentication tests
├── test_ca_service.py       # CA service unit tests
├── test_cert_service.py     # Certificate service unit tests
├── test_api.py             # API integration tests
└── test_parser_service.py   # Parser service tests
```

**Running Tests:**
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific markers
pytest -m unit              # Unit tests only
pytest -m integration       # Integration tests only
pytest -m requires_openssl  # Tests requiring OpenSSL
```

**Test Categories:**
- **Unit Tests** (`@pytest.mark.unit`): Test individual services and functions
- **Integration Tests** (`@pytest.mark.integration`): Test API endpoints and full workflows
- **Slow Tests** (`@pytest.mark.slow`): Long-running tests
- **OpenSSL Required** (`@pytest.mark.requires_openssl`): Tests requiring OpenSSL in PATH

**Key Fixtures:**
- `ca_data_dir` - Temporary CA data directory for tests
- `ca_service` - CA service instance
- `cert_service` - Certificate service instance
- `client` - FastAPI test client
- `created_root_ca` - Pre-created root CA for testing
- `created_intermediate_ca` - Pre-created intermediate CA

**Test Coverage Goals:**
- Services: >90%
- API endpoints: >85%
- Overall: >80%

**What to Test:**
- Certificate creation flows (RSA, ECDSA, Ed25519)
- OpenSSL command generation
- Path handling (Windows and Linux)
- YAML serialization/deserialization
- API request/response validation
- Error handling and edge cases
- Certificate validity status
- Format conversion (PEM to Text)

## API Documentation

HomeLab PKI uses FastAPI's automatic OpenAPI documentation:

**Available Endpoints:**
- `/docs` - Swagger UI (interactive API documentation)
- `/redoc` - ReDoc (alternative documentation format)
- `/openapi.json` - OpenAPI schema (machine-readable)

The API documentation is automatically generated from:
- Route decorators and type hints
- Pydantic model schemas
- Docstrings in route functions

**To enhance API docs:**
1. Add detailed docstrings to route functions
2. Use response_model parameter in route decorators
3. Add tags to organize endpoints
4. Include examples in Pydantic models

## Configuration

`config.yaml` structure:
```yaml
app:
  title: "HomeLab PKI"
  debug: false

paths:
  ca_data: "./ca-data"
  logs: "./logs"

defaults:
  root_ca:
    validity_days: 3650
  intermediate_ca:
    validity_days: 1825
  server_cert:
    validity_days: 365
```

## API Endpoints

### CAs
- `POST /api/cas` - Create CA (root or intermediate)
- `GET /api/cas` - List root CAs
- `GET /api/cas/{ca_id}` - Get CA details
- `DELETE /api/cas/{ca_id}` - Delete CA

### Certificates
- `POST /api/certs` - Create certificate
- `GET /api/certs/{ca_id}/list` - List certificates for CA
- `GET /api/certs/{cert_id}` - Get certificate details
- `DELETE /api/certs/{cert_id}` - Delete certificate

### Downloads
- `GET /download/ca/{ca_id}/cert` - Download CA certificate
- `GET /download/ca/{ca_id}/key` - Download CA private key
- `GET /download/cert/{cert_id}/cert` - Download certificate
- `GET /download/cert/{cert_id}/key` - Download private key
- `GET /download/cert/{cert_id}/fullchain` - Download full chain

## Web Routes

### Dashboard
- `GET /` - Dashboard with statistics

### Root CAs
- `GET /rootcas` - List root CAs
- `GET /rootcas/create` - Create root CA form
- `GET /rootcas/{ca_id}` - Root CA detail

### Intermediate CAs
- `GET /intermediates` - List all intermediate CAs
- `GET /intermediates/create` - Create intermediate CA form
- `GET /intermediates/{ca_id}` - Intermediate CA detail

### Certificates
- `GET /certs` - List all certificates
- `GET /certs/create` - Create certificate form
- `GET /certs/{cert_id}` - Certificate detail

## Troubleshooting

### Common Errors

**"OpenSSL not found in PATH"**
- Ensure OpenSSL is installed and in system PATH
- Test with: `openssl version`

**"could not determine a constructor for the tag"**
- Enum serialization issue
- Check `yaml_service.py` has Enum representer registered
- Verify Enums are converted to `.value` before saving

**"No such file or directory" when creating certificates**
- Path resolution issue
- Check `_path_to_posix()` uses `path.resolve()` for absolute paths
- Verify working directory is correct

**"No module named 'app.config'"**
- Import error in routes
- Use `ca_service.ca_data_dir` instead of importing settings
- Services have direct access to ca_data_dir attribute

## Version History

### Current Version: 1.0.0

**v1.0.0 Release (December 2025):**
- First stable release
- Air-gapped operation: All frontend assets bundled locally (Bootstrap 5.3, Bootstrap Icons 1.11)
- Parent CA preselection when creating certificates/intermediate CAs from detail pages
- Comprehensive test suite with pytest (88 tests, >80% coverage)
- Full documentation (README, CLAUDE.md, THIRD_PARTY_LICENSES.md)

**Previous Changes:**
- Root CA, Intermediate CA, and Server Certificate management
- Certificate extensions (Key Usage, Extended Key Usage) with presets
- CSR signing and certificate import functionality
- Multiple key algorithms (RSA, ECDSA, Ed25519)
- RESTful API with OpenAPI documentation
- Web interface with Bootstrap 5 and dark mode
- Password-based authentication with session management
- Soft delete (trash) for CAs and certificates
- Live OpenSSL command preview during creation
- Dashboard with certificate expiration overview

## Future Considerations

### Roadmap Items
- Certificate Revocation Lists (CRL)
- OCSP Responder
- Certificate Templates
- Bulk Operations
- Certificate Renewal
- Email Notifications
- HSM Support
- ACME Protocol
- Docker Image
- Multi-User Support

---

**Last Updated**: December 2025
**Maintained for**: Claude AI Assistant context
