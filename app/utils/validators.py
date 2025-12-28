"""Input validation utilities."""

import re
from pathlib import Path


def sanitize_name(name: str) -> str:
    """
    Sanitize name for use in file paths.

    Converts to lowercase, replaces spaces with hyphens,
    removes non-alphanumeric characters (except hyphens).

    Args:
        name: Name to sanitize

    Returns:
        Sanitized name

    Example:
        >>> sanitize_name("My Root CA")
        'my-root-ca'
    """
    # Convert to lowercase
    sanitized = name.lower()
    # Replace spaces with hyphens
    sanitized = sanitized.replace(" ", "-")
    # Remove non-alphanumeric characters (except hyphens)
    sanitized = re.sub(r"[^a-z0-9-]", "", sanitized)
    # Remove multiple consecutive hyphens
    sanitized = re.sub(r"-+", "-", sanitized)
    # Remove leading/trailing hyphens
    sanitized = sanitized.strip("-")

    return sanitized


def validate_ca_path(ca_data_dir: Path, ca_id: str) -> Path:
    """
    Validate and construct CA path.

    Args:
        ca_data_dir: Base CA data directory
        ca_id: CA identifier

    Returns:
        Full CA path

    Raises:
        ValueError: If path is invalid or doesn't exist
    """
    ca_path = ca_data_dir / ca_id

    # Check for directory traversal attempts
    if ".." in ca_id or ca_id.startswith("/"):
        raise ValueError(f"Invalid CA ID: {ca_id}")

    # Verify path exists
    if not ca_path.exists():
        raise ValueError(f"CA not found: {ca_id}")

    # Verify it's actually within ca_data_dir
    try:
        ca_path.resolve().relative_to(ca_data_dir.resolve())
    except ValueError:
        raise ValueError(f"Invalid CA path: {ca_id}")

    return ca_path


def validate_common_name(cn: str) -> None:
    """
    Validate common name format.

    Args:
        cn: Common name to validate

    Raises:
        ValueError: If common name is invalid
    """
    if not cn or len(cn.strip()) == 0:
        raise ValueError("Common name cannot be empty")

    if len(cn) > 64:
        raise ValueError("Common name too long (max 64 characters)")


def validate_country_code(country: str) -> None:
    """
    Validate ISO 3166-1 alpha-2 country code.

    Args:
        country: Country code to validate

    Raises:
        ValueError: If country code is invalid
    """
    if not re.match(r"^[A-Z]{2}$", country):
        raise ValueError("Country code must be 2 uppercase letters (ISO 3166-1 alpha-2)")


def validate_domain(domain: str) -> None:
    """
    Validate domain name format.

    Args:
        domain: Domain name to validate

    Raises:
        ValueError: If domain is invalid
    """
    # Allow wildcards
    domain_pattern = r"^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}$"

    if not re.match(domain_pattern, domain):
        raise ValueError(f"Invalid domain format: {domain}")
