#!/usr/bin/env python3
"""
Migration script to convert absolute paths to relative paths in config.yaml files.

This script:
1. Finds all config.yaml files under ca-data (including _trash)
2. Updates openssl_command fields that contain absolute paths
3. Converts them to relative paths

For intermediate CAs: ../ca.crt, ../ca.key
For certificates: ../../ca.crt, ../../ca.key
"""

import re
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.services.yaml_service import YAMLService


def convert_absolute_to_relative(openssl_command: str, config_type: str) -> str:
    """
    Convert absolute paths in openssl_command to relative paths.

    Args:
        openssl_command: The OpenSSL command string
        config_type: Either 'intermediate_ca' or 'server_cert'

    Returns:
        Command string with relative paths
    """
    if not openssl_command or openssl_command.startswith("#"):
        return openssl_command

    # Determine relative path based on config type
    if config_type == "intermediate_ca":
        relative_prefix = "../"
    elif config_type == "server_cert":
        relative_prefix = "../../"
    else:
        return openssl_command  # Root CAs don't need conversion

    # Pattern to match absolute paths to ca.crt and ca.key
    # Handles both Windows (D:/...) and Unix (/home/...) style paths
    # Also handles paths with forward slashes on Windows (as used by OpenSSL)

    # Pattern matches: -CA <path>/ca.crt or -CAkey <path>/ca.key
    # Where <path> is an absolute path containing at least one '/'

    result = openssl_command

    # Replace -CA <absolute_path>/ca.crt with -CA ../ca.crt or ../../ca.crt
    result = re.sub(r"-CA\s+[A-Za-z]?:?/[^\s]+/ca\.crt", f"-CA {relative_prefix}ca.crt", result)

    # Replace -CAkey <absolute_path>/ca.key with -CAkey ../ca.key or ../../ca.key
    result = re.sub(r"-CAkey\s+[A-Za-z]?:?/[^\s]+/ca\.key", f"-CAkey {relative_prefix}ca.key", result)

    return result


def migrate_config_file(config_path: Path, dry_run: bool = False) -> bool:
    """
    Migrate a single config.yaml file.

    Args:
        config_path: Path to the config.yaml file
        dry_run: If True, only print what would be changed

    Returns:
        True if file was modified, False otherwise
    """
    try:
        config_data = YAMLService.load_config_yaml(config_path)
    except Exception as e:
        print(f"  ERROR: Failed to load {config_path}: {e}")
        return False

    config_type = config_data.get("type")
    openssl_command = config_data.get("openssl_command", "")

    if not openssl_command:
        return False

    # Check if command contains absolute paths
    if not (
        re.search(r"-CA\s+[A-Za-z]?:?/[^\s]+/ca\.crt", openssl_command)
        or re.search(r"-CAkey\s+[A-Za-z]?:?/[^\s]+/ca\.key", openssl_command)
    ):
        return False

    # Convert to relative paths
    new_command = convert_absolute_to_relative(openssl_command, config_type)

    if new_command == openssl_command:
        return False

    print(f"  Migrating: {config_path}")
    print(f"    Type: {config_type}")

    if dry_run:
        print(f"    Would update openssl_command")
        print(f"    Old (excerpt): ...{openssl_command[-100:] if len(openssl_command) > 100 else openssl_command}")
        print(f"    New (excerpt): ...{new_command[-100:] if len(new_command) > 100 else new_command}")
    else:
        config_data["openssl_command"] = new_command
        YAMLService.save_config_yaml(config_path, config_data)
        print(f"    Updated successfully")

    return True


def main():
    """Main migration function."""
    import argparse

    parser = argparse.ArgumentParser(description="Migrate config.yaml files from absolute to relative paths")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be changed without making changes")
    parser.add_argument(
        "--ca-data-dir",
        type=Path,
        default=Path(__file__).parent.parent / "ca-data",
        help="Path to ca-data directory (default: ../ca-data)",
    )

    args = parser.parse_args()

    ca_data_dir = args.ca_data_dir.resolve()

    if not ca_data_dir.exists():
        print(f"ERROR: ca-data directory not found: {ca_data_dir}")
        sys.exit(1)

    print(f"Scanning: {ca_data_dir}")
    print(f"Dry run: {args.dry_run}")
    print()

    # Find all config.yaml files
    config_files = list(ca_data_dir.rglob("config.yaml"))

    print(f"Found {len(config_files)} config.yaml files")
    print()

    migrated_count = 0

    for config_path in config_files:
        if migrate_config_file(config_path, args.dry_run):
            migrated_count += 1

    print()
    if args.dry_run:
        print(f"Would migrate {migrated_count} files")
        print("Run without --dry-run to apply changes")
    else:
        print(f"Migrated {migrated_count} files")


if __name__ == "__main__":
    main()
