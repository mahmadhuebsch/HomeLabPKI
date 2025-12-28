# YACertManager

<div align="center">

**Yet Another Certificate Manager** - A web-based Certificate Authority (CA) management system

[![CI](https://github.com/mahmadhuebsch/YACertManager/actions/workflows/ci.yml/badge.svg)](https://github.com/mahmadhuebsch/YACertManager/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green.svg)](https://fastapi.tiangolo.com/)
[![OpenSSL](https://img.shields.io/badge/OpenSSL-1.1.1+-red.svg)](https://www.openssl.org/)

[Features](#features) • [Installation](#installation) • [Configuration](#configuration) • [API](#api-documentation) • [Contributing](#contributing)

</div>

---

## Overview

YACertManager is a web-based Certificate Authority management system built with FastAPI and Bootstrap 5.
It provides comprehensive tools for creating and managing Root CAs, Intermediate CAs, and server certificates through a
streamlined web interface.

Designed for development environments, testing infrastructure, internal PKI deployments, and certificate management operations.

![screenshot-cert-detail.png](.github/images/screenshot-cert-detail.png)

## Features

- **Root CA Management** - Create and manage self-signed Root Certificate Authorities
- **Intermediate CA Support** - Build certificate chains with Intermediate CAs
- **Server Certificates** - Issue certificates with Subject Alternative Names (SANs)
- **CSR Signing** - Sign external Certificate Signing Requests where private keys are managed externally
- **Importing** - Import and track externally-signed CAs and certificates
- **Multiple Certificate Formats** - View certificates in both Text (human-readable) and PEM formats
- **Modern Web Interface** - Responsive Bootstrap 5 UI with organized navigation
- **RESTful API** - Complete API with OpenAPI documentation

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [Configuration](#configuration)
- [API Documentation](#api-documentation)
- [Testing](#testing)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [Planned Features](#planned-features)
- [License](#license)

## Requirements

- Python 3.10 or higher
- OpenSSL 1.1.1 or higher (must be available in system PATH)

## Installation

```bash
# Clone the repository
git clone https://github.com/mahmadhuebsch/YACertManager.git
cd YACertManager

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
```

## Quick Start

```bash
# Start the application
python main.py
```

The application will be accessible at `http://localhost:8000`.

### First Steps

1. Navigate to `http://localhost:8000`
2. Create a Root CA from the dashboard
3. Optionally create an Intermediate CA under the Root CA
4. Issue server certificates as needed

## Project Structure

```
YACertManager/
├── app/
│   ├── api/                  # REST API endpoints
│   │   └── routes/           # API route handlers
│   ├── models/               # Pydantic models
│   ├── services/             # Business logic
│   ├── templates/            # Jinja2 HTML templates
│   ├── utils/                # Utility functions
│   └── web/                  # Web routes
├── tests/                    # Test files
├── ca-data/                  # Runtime CA storage (gitignored)
├── main.py                   # Application entry point
├── config.yaml               # Application configuration
├── requirements.txt          # Production dependencies
└── requirements-dev.txt      # Development dependencies
```

## Configuration

Edit `config.yaml` to customize application behavior:

```yaml
# Example configuration
app:
  title: "YACertManager"
  debug: false

paths:
  ca_data: "./ca-data"      # Certificate storage location
  logs: "./logs"            # Log file location

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

logging:
  level: "INFO"
```

## API Documentation

YACertManager provides a complete RESTful API with automatic interactive documentation powered by FastAPI.

### Access the API Documentation

- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`
- **OpenAPI Schema**: `http://localhost:8000/openapi.json`

## Security Considerations

> **Important**: YACertManager is designed for development, testing, and internal infrastructure. For production PKI, consider enterprise-grade solutions.

### Key Security Notes

- **Private Key Storage**: Private keys are stored unencrypted on disk. It is highly recommended to choose a strong password and/or encrypt the `ca-data` directory at the file system level (e.g. [Cryptomator](https://github.com/cryptomator/cryptomator)).
- **Access Control**: No built-in authentication. Deploy behind a reverse proxy with authentication for network access.
- **HTTPS**: Always use HTTPS when deploying in any networked environment.
- **Backup**: Regularly backup the `ca-data` directory.

### Best Practices

1. **Offline Root CA**: Keep Root CA keys offline, use Intermediate CAs for day-to-day operations
2. **Short-Lived Certificates**: Use shorter validity periods (90-365 days) for server certificates
3. **Regular Rotation**: Rotate certificates before expiration
4. **Monitoring**: Monitor certificate expiration dates from the dashboard

For detailed security information, see [SECURITY.md](SECURITY.md).

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting a pull request.

### Development Setup

```bash
# Clone and setup
git clone https://github.com/mahmadhuebsch/YACertManager.git
cd YACertManager
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

- [ ] Password Support
- [ ] Email notifications for expiring certificates
- [ ] ACME Protocol support
- [ ] Docker containerization

## License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

Made with :heart: by the YACertManager Contributors

</div>
