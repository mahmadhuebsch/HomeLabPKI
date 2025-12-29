# Contributing to HomeLab PKI

Thank you for your interest in contributing to HomeLab PKI! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

## How to Contribute

### Reporting Bugs

Before creating a bug report, please check existing issues to avoid duplicates.

When creating a bug report, include:
- A clear, descriptive title
- Steps to reproduce the issue
- Expected vs actual behavior
- Your environment (OS, Python version, OpenSSL version)
- Relevant logs or error messages

### Suggesting Features

Feature requests are welcome! Please include:
- A clear description of the feature
- The problem it solves or use case
- Any implementation ideas you have

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Set up your development environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # or .venv\Scripts\activate on Windows
   pip install -r requirements-dev.txt
   ```
3. **Make your changes** following our coding standards
4. **Add tests** for any new functionality
5. **Run the test suite** to ensure all tests pass:
   ```bash
   pytest tests/ -v
   ```
6. **Update documentation** if needed
7. **Submit a pull request** with a clear description of your changes

## Development Setup

### Prerequisites

- Python 3.10 or higher
- OpenSSL 1.1.1 or higher

### Installation

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/HomeLabPKI.git
cd HomeLabPKI

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# or: .venv\Scripts\activate  # Windows

# Install development dependencies
pip install -r requirements-dev.txt

# Verify OpenSSL
openssl version

# Run tests
pytest tests/ -v
```

### Running the Application

```bash
python main.py
```

The application will be available at `http://localhost:8000`.

## Coding Standards

### Python Style

- Follow PEP 8 guidelines
- Use 4 spaces for indentation
- Maximum line length: 120 characters
- Use type hints for function parameters and return values
- Write docstrings for public functions and classes

### Code Quality Tools

```bash
# Format code with black
black app/ tests/

# Sort imports
isort app/ tests/

# Check code style
flake8 app/ tests/

# Type checking
mypy app/
```

### Testing

- Write tests for all new functionality
- Maintain or improve code coverage
- Use pytest fixtures for common setup
- Mark tests appropriately (`@pytest.mark.unit`, `@pytest.mark.integration`)

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=app --cov-report=html

# Run specific test file
pytest tests/test_api.py -v
```

## Project Structure

```
HomeLabPKI/
├── app/
│   ├── api/          # REST API endpoints
│   ├── models/       # Pydantic models
│   ├── services/     # Business logic
│   ├── templates/    # Jinja2 templates
│   ├── utils/        # Utility functions
│   └── web/          # Web routes
├── tests/            # Test files
├── ca-data/          # Runtime CA storage (gitignored)
└── main.py           # Application entry point
```

## Commit Messages

Write clear, concise commit messages:
- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters
- Reference issues and pull requests when relevant

Examples:
- `Add CSR signing functionality`
- `Fix certificate chain validation bug`
- `Update README with installation instructions`

## Questions?

If you have questions, feel free to:
- Open an issue for discussion
- Check existing documentation and issues

Thank you for contributing!
