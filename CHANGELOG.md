# Changelog

All notable changes to YACertManager will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Root CA creation and management
- Intermediate CA support with certificate chains
- CSR (Certificate Signing Request) signing
- Certificate import functionality
- RESTful API with OpenAPI documentation
- Web interface with Bootstrap 5
- Certificate download functionality (cert, key, chain, fullchain)
- Dashboard with certificate expiration overview

### Security
- Private key download confirmation dialogs
- Security warnings for unencrypted key storage
- Documentation for deployment security best practices

## [1.0.0] - TBD

### Added
- First stable release

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
