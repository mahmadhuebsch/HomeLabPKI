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

### 4. CSR Service (`app/services/csr_service.py`)
- Manages Certificate Signing Requests for external CAs
- CSRs are stored in `ca-data/csrs/` directory (standalone, not under any CA)
- Key methods:
  - `create_csr()` - Generate CSR and encrypted private key
  - `get_csr()` - Get CSR details by ID
  - `list_csrs()` - List all CSRs with optional status filter
  - `delete_csr()` - Move CSR to trash (soft delete)
  - `mark_signed()` - Import signed certificate from external CA
  - `get_csr_content()` - Get PEM content
- CSR IDs: `{sanitized_cn}` (e.g., `example-com`)
- CSR Directory Structure:
  ```
  ca-data/csrs/{csr-id}/
  ├── csr.pem          # Certificate Signing Request
  ├── key.pem          # Private key (AES-256 encrypted)
  ├── cert.pem         # Signed certificate (after import)
  ├── chain.pem        # Certificate chain (optional)
  └── config.yaml      # CSR configuration
  ```
- CSR Status: `pending`, `signed`, `expired`
- Workflow:
  1. User creates CSR with encrypted private key
  2. User downloads CSR and submits to external CA (DigiCert, Let's Encrypt, etc.)
  3. User receives signed certificate from CA
  4. User imports signed certificate (system validates public key match)
  5. CSR status changes to `signed`

### 5. CRL Service (`app/services/crl_service.py`)
- Manages Certificate Revocation Lists for each CA
- **RFC Compliance**: Implements RFC 5280 (CRL profile) and RFC 2585 (HTTP distribution)
- Each CA maintains: index.txt (OpenSSL database), crlnumber, crl/ directory
- Key methods:
  - `initialize_crl_files()` - Create CRL infrastructure for CA
  - `revoke_certificate()` - Add cert to CRL + auto-regenerate
  - `unrevoke_certificate()` - Remove hold (certificateHold only)
  - `generate_crl()` - Generate/regenerate CRL
  - `get_crl_info()` - Get CRL metadata
  - `list_revoked_certificates()` - List revoked certs for CA
- Supports all 10 RFC 5280 revocation reasons
- Auto-generates both PEM and DER format CRLs
- **Public CRL Endpoint**: `/download/crl/{ca_id}.crl` (no authentication per RFC 2585)
- CRL Directory Structure:
  ```
  ca-data/root-ca-example/
  ├── index.txt          # OpenSSL certificate database
  ├── index.txt.attr     # Database attributes
  ├── crlnumber          # CRL serial counter
  ├── crl/
  │   ├── crl.pem        # CRL in PEM format
  │   ├── crl.der        # CRL in DER format
  │   └── config.yaml    # CRL metadata
  ```
- **RFC 5280 Revocation Reasons**:
  - `unspecified` - No specific reason
  - `keyCompromise` - Private key compromised
  - `cACompromise` - CA compromised
  - `affiliationChanged` - Subject's affiliation changed
  - `superseded` - Certificate replaced
  - `cessationOfOperation` - CA/subject ceased operations
  - `certificateHold` - Temporary hold (only reversible reason)
  - `removeFromCRL` - Remove from CRL (delta CRL)
  - `privilegeWithdrawn` - Privilege withdrawn
  - `aACompromise` - Attribute Authority compromised

### 6. SMTP Service (`app/services/smtp_service.py`)
- Handles email sending via SMTP
- Supports multiple encryption modes (none, STARTTLS, SSL)
- Key methods:
  - `test_connection()` - Test SMTP server connection and authentication
  - `send_email()` - Send single email with HTML and text versions
  - `send_bulk_email()` - Send to multiple recipients
- Async implementation using aiosmtplib
- Handles authentication, timeouts, and error reporting
- Encryption modes:
  - `none` - Plain SMTP (port 25)
  - `starttls` - Start unencrypted, upgrade to TLS (port 587, recommended)
  - `ssl` - Implicit TLS from start (port 465)

### 7. Notification Service (`app/services/notification_service.py`)
- Manages certificate expiration notifications
- **Key Features**:
  - Automated expiration checking with configurable thresholds
  - State tracking to prevent duplicate notifications
  - Per-entity notification overrides
  - Email template rendering with Jinja2
  - Background scheduling via APScheduler
- Key methods:
  - `check_expirations()` - Check all entities for expiration and send notifications
  - `send_test_email()` - Send test email to verify SMTP configuration
  - `reset_state()` - Reset notification state (all or specific entity)
  - `_check_entity()` - Check single entity against thresholds
  - `_send_expiry_notification()` - Send notification email
- State tracking:
  - Stored in `ca-data/.notifications/state.yaml`
  - Tracks which thresholds have been sent per entity
  - Prevents duplicate notifications
- Notification logs:
  - Monthly log files in `ca-data/.notifications/log/`
  - Records all sent notifications with status
- Entity overrides:
  - Stored in entity's `config.yaml` under `notifications` key
  - Can customize recipients, thresholds, and enabled state
  - Recipients are **added** to global list, thresholds **replace** global
- Email templates:
  - HTML and text versions in `app/templates/email/`
  - Variables: entity_type, entity_name, expiry_date, days_remaining, etc.
  - Supports internal URLs if CRL base_url is configured
- Background scheduler:
  - Runs in main.py using APScheduler
  - Configurable interval (default 24 hours)
  - Optional startup check

### 8. Parser Service (`app/services/parser_service.py`)
- Parses X.509 certificates using cryptography library
- Converts certificates to text format using OpenSSL
- Converts CSRs to text format using OpenSSL
- Extracts Key Usage and Extended Key Usage extensions
- Key methods:
  - `parse_certificate()` - Extract certificate data including extensions
  - `certificate_to_text()` - Convert to human-readable text format
  - `csr_to_text()` - Convert CSR to human-readable text format
  - `get_csr_public_key_fingerprint()` - Get CSR public key fingerprint for matching
  - `verify_cert_matches_csr()` - Verify certificate matches CSR public key
  - `get_validity_status()` - Check expiration status
  - `verify_key_pair()` - Verify cert/key match
  - `_extract_key_usage()` - Extract Key Usage extension values
  - `_extract_extended_key_usage()` - Extract Extended Key Usage values

### 9. YAML Service (`app/services/yaml_service.py`)
- Handles YAML serialization/deserialization
- **IMPORTANT**: Custom Enum handling to prevent serialization errors
- Converts Enum objects to their `.value` property before saving
- Key methods:
  - `save_config_yaml()` - Save config with Enum handling
  - `load_config_yaml()` - Load config

## Recent Features & Changes

### Email Notifications (v1.1.0)
- **Automated Expiration Monitoring**: Background scheduler checks for expiring CAs, certificates, and CRLs
- **SMTP Integration**: Send notifications via any SMTP server (Gmail, Outlook, internal mail servers)
- **Configurable Thresholds**: Multiple notification intervals (e.g., 90, 60, 30, 14, 7 days before expiry)
- **State Tracking**: Prevents duplicate notifications for same threshold
- **Per-Entity Overrides**: Custom notification settings in entity's config.yaml
- **Web UI Integration**: Settings page with SMTP testing, test email sending, and manual expiration checks
- **API Endpoints**: Full REST API for notification management
- **Email Templates**: HTML and text templates with Jinja2 rendering
- **Background Scheduler**: APScheduler runs periodic checks based on configured interval
- **Security Options**: Environment variable support for SMTP passwords, configurable email content

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

crl:
  # Base URL for CRL Distribution Point in certificates
  # Example: "http://pki.example.com:8000"
  # If set, certificates will include CDP extension
  base_url: null
  validity_days: 30

smtp:
  enabled: false
  host: smtp.example.com
  port: 587
  encryption: starttls  # none, starttls, ssl
  username: null
  password: null  # Consider using environment variables
  sender_email: pki@example.com
  sender_name: HomeLab PKI
  timeout_seconds: 30

notifications:
  enabled: false
  recipients: []
  thresholds: [90, 60, 30, 14, 7, 3, 1]
  check_interval_hours: 24
  check_on_startup: true
  include_ca_expiry: true
  include_cert_expiry: true
  include_crl_expiry: true
  digest_mode: false

email_templates:
  subject_warning: "[HomeLab PKI] {{ entity_type }} '{{ entity_name }}' expires in {{ days_remaining }} days"
  subject_expired: "[HomeLab PKI] EXPIRED: {{ entity_type }} '{{ entity_name }}'"
  subject_test: "[HomeLab PKI] Test Email"
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

### CSRs
- `POST /api/csrs` - Create new CSR
- `GET /api/csrs` - List CSRs (optional status filter)
- `GET /api/csrs/{csr_id}` - Get CSR details
- `DELETE /api/csrs/{csr_id}` - Delete CSR
- `POST /api/csrs/{csr_id}/signed` - Import signed certificate
- `GET /api/csrs/{csr_id}/download/csr` - Download CSR file
- `GET /api/csrs/{csr_id}/download/key` - Download private key

### CRLs
- `POST /api/certs/{cert_id}/revoke` - Revoke certificate
- `POST /api/certs/{cert_id}/unrevoke` - Remove hold
- `GET /api/cas/{ca_id}/crl` - Get CRL info
- `GET /api/cas/{ca_id}/crl/revoked` - List revoked certs
- `POST /api/cas/{ca_id}/crl/regenerate` - Manual regenerate
- `GET /download/ca/{ca_id}/crl` - Download CRL (PEM, requires auth)
- `GET /download/ca/{ca_id}/crl/der` - Download CRL (DER, requires auth)
- `GET /download/crl/{ca_id}.crl` - **PUBLIC** CRL endpoint (DER, no auth per RFC 2585)

### Notifications
- `GET /api/notifications/status` - Get notification system status
- `POST /api/notifications/check` - Trigger manual expiration check
- `POST /api/notifications/test` - Send test email
- `POST /api/notifications/smtp/test` - Test SMTP connection
- `POST /api/notifications/reset` - Reset all notification state
- `POST /api/notifications/reset/{entity_id}` - Reset state for specific entity
- `GET /api/notifications/config` - Get notification configuration

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

### CSRs
- `GET /certs/csrs` - CSR list page
- `GET /certs/csrs/create` - CSR creation form
- `GET /certs/csrs/{csr_id}` - CSR detail page
- `GET /certs/csrs/{csr_id}/import-signed` - Import signed certificate form

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

### Current Version: 1.2.0

**v1.2.0 Release (February 2026):**
- **Certificate Revocation Lists (CRL)**: Full RFC 5280/2585 compliant CRL support
  - Revoke certificates with 10 standard revocation reasons (keyCompromise, cACompromise, etc.)
  - Auto-regenerate CRL on certificate revocation
  - Public CRL endpoint (no authentication required per RFC 2585)
  - CRL Distribution Point (CDP) extension in certificates
  - Support for certificate hold (reversible revocation)
  - Download CRLs in PEM and DER formats
  - Per-CA CRL management with index.txt database
  - Revoked certificate listing and status tracking
- **Email Notifications**: Automated certificate expiration monitoring via SMTP
  - Configurable thresholds for expiration warnings (e.g., 90, 60, 30, 14, 7 days)
  - Background scheduler for periodic expiration checks
  - Per-entity notification overrides (custom recipients and thresholds)
  - State tracking to prevent duplicate notifications
  - Support for CA, certificate, and CRL expiration monitoring
  - HTML and text email templates with Jinja2 rendering
  - Environment variable support for SMTP credentials
  - Web UI integration: test SMTP, send test emails, manual checks
  - Rate limiting and error handling for reliable delivery
  - Digest mode for consolidated expiration reports
- **Enhanced Configuration**: Extended config.yaml with CRL and SMTP/notification settings
- **Bug Fixes**: Import sorting and CI pipeline improvements

**v1.1.0 Release (January 2026):**
- **CSR (Certificate Signing Request) Feature**: Generate CSRs for external CAs with encrypted private keys
  - CSR creation with all standard certificate fields and extensions
  - Download CSR and encrypted private key files
  - Import signed certificates from external CAs with public key validation
  - CSR status tracking (pending, signed, expired)
  - Full web UI with creation, detail, and import forms
- **Full Chain Import**: Import complete certificate chains in single operation
  - Support for importing root + intermediate(s) + certificate chains
  - Automatic chain validation and parent-child relationship verification
  - Migration script for existing installations to use relative paths
- **Enhanced Security**: Private key passwords no longer stored in config files
  - Passwords required at runtime for signing operations
  - Only encryption status flag stored in configuration
  - Migration script provided for existing installations
- **Improved User Experience**: Enhanced error messages and field validation
- **Testing**: Added Playwright browser tests for authentication flows
- **Docker**: GitHub Container Registry (GHCR) support with automated builds

**v1.0.0 Release (December 2025):**
- First stable release
- Air-gapped operation: All frontend assets bundled locally (Bootstrap 5.3, Bootstrap Icons 1.11)
- Parent CA preselection when creating certificates/intermediate CAs from detail pages
- Comprehensive test suite with pytest (>80% coverage)
- Full documentation (README, CLAUDE.md, THIRD_PARTY_LICENSES.md)
- Root CA, Intermediate CA, and Server Certificate management
- Certificate extensions (Key Usage, Extended Key Usage) with presets
- CSR signing functionality (sign external CSRs)
- Multiple key algorithms (RSA, ECDSA, Ed25519)
- RESTful API with OpenAPI documentation
- Web interface with Bootstrap 5 and dark mode
- Password-based authentication with session management
- Soft delete (trash) for CAs and certificates
- Live OpenSSL command preview during creation
- Dashboard with certificate expiration overview

## Future Considerations

### Roadmap Items
- OCSP Responder
- Certificate Templates
- Bulk Operations
- Certificate Renewal
- HSM Support
- ACME Protocol
- Multi-User Support

---

**Last Updated**: February 2026
**Maintained for**: Claude AI Assistant context
