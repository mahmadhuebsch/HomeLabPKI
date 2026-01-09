# Changelog

All notable changes to HomeLab PKI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Fixed

## [1.1.0] - 2026-01-09

### Added
- **CSR (Certificate Signing Request) Feature**: Generate CSRs for submission to external CAs (DigiCert, Let's Encrypt, etc.)
  - Create CSRs with encrypted private keys stored locally
  - Download CSR and private key files
  - Import signed certificates back from external CAs
  - CSR status tracking (pending, signed, expired)
  - Public key matching validation when importing signed certificates
- **Full Chain Import**: Import complete certificate chains in a single operation
  - Import root CA + intermediate CA(s) + end-entity certificate together
  - Automatic chain validation and verification
  - Support for importing partial chains (root + intermediates, or just root)
- **Enhanced Field Validation**: Improved input validation across all forms
- **Docker GHCR Support**: Container images now available from GitHub Container Registry

### Changed
- **Default Password**: Changed default admin password for improved security
- **CI/CD Improvements**: Enhanced GitHub Actions workflow with tag-based triggers and `latest` Docker tag support

### Security
- **Private Key Password Handling**: Private key passwords are no longer stored in configuration files
  - Passwords required at runtime for operations that need private key access
  - Only encryption status flag (`encrypted: true/false`) stored in config
  - Migration script provided for existing installations
- **Enhanced Error Messages**: Improved error feedback without exposing sensitive information

### Fixed
- **Code Quality**: Fixed flake8 forward reference errors
- **Import Sorting**: Resolved isort compliance issues
- **Security Documentation**: Updated SECURITY.md to reflect encrypted password storage

## [1.0.0] - 2025-12-29

### Added
- Root CA creation and management
- Intermediate CA support with certificate chains
- Server certificate issuance with Subject Alternative Names (SANs)
- Certificate extensions support (Key Usage, Extended Key Usage) with presets
- CSR (Certificate Signing Request) signing
- Certificate and CA import functionality
- Multiple key algorithms: RSA (2048, 4096, 8192), ECDSA (P-256, P-384, P-521), Ed25519
- RESTful API with OpenAPI documentation (Swagger UI, ReDoc)
- Web interface with Bootstrap 5
- Certificate download functionality (cert, key, chain, fullchain)
- Dashboard with certificate expiration overview
- Dark mode support
- Password-based authentication with session management
- Air-gapped operation (all assets bundled locally)
- Docker support
- Soft delete (trash) for CAs and certificates

### Security
- Private key download confirmation dialogs
- Security warnings for unencrypted key storage
- CSRF protection for web forms
- Documentation for deployment security best practices

---

## Version History

### Versioning Scheme

- **MAJOR**: Incompatible API changes
- **MINOR**: New functionality (backwards compatible)
- **PATCH**: Bug fixes (backwards compatible)

### Release Process

1. Update version in relevant files
2. Update CHANGELOG.md
3. Create git tag
4. Push tag to trigger release workflow
