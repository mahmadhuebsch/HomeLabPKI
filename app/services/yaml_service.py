"""YAML file operations service."""

import yaml
from pathlib import Path
from typing import Any, Dict
from datetime import datetime
from enum import Enum
import logging

logger = logging.getLogger("yacertmanager")


class YAMLService:
    """Service for YAML file operations."""

    @staticmethod
    def load_yaml(file_path: Path) -> Dict[str, Any]:
        """
        Load YAML file and return as dictionary.

        Args:
            file_path: Path to YAML file

        Returns:
            Parsed YAML content as dictionary

        Raises:
            FileNotFoundError: If file doesn't exist
            yaml.YAMLError: If file is not valid YAML
        """
        if not file_path.exists():
            raise FileNotFoundError(f"YAML file not found: {file_path}")

        with open(file_path, 'r', encoding='utf-8') as f:
            try:
                data = yaml.safe_load(f)
                logger.debug(f"Loaded YAML from: {file_path}")
                return data or {}
            except yaml.YAMLError as e:
                logger.error(f"Error parsing YAML file {file_path}: {e}")
                raise

    @staticmethod
    def save_yaml(file_path: Path, data: Dict[str, Any]) -> None:
        """
        Save dictionary to YAML file.

        Args:
            file_path: Path to save YAML file
            data: Data to save

        Raises:
            yaml.YAMLError: If data cannot be serialized to YAML
        """
        # Ensure parent directory exists
        file_path.parent.mkdir(parents=True, exist_ok=True)

        # Custom representer for datetime objects
        def datetime_representer(dumper, data):
            return dumper.represent_scalar('tag:yaml.org,2002:timestamp',
                                          data.isoformat())

        # Custom representer for Enum objects
        def enum_representer(dumper, data):
            return dumper.represent_scalar('tag:yaml.org,2002:str', data.value)

        yaml.add_representer(datetime, datetime_representer)
        yaml.add_representer(Enum, enum_representer)

        # Add representers for all Enum subclasses
        yaml.add_multi_representer(Enum, enum_representer)

        with open(file_path, 'w', encoding='utf-8') as f:
            try:
                yaml.dump(
                    data,
                    f,
                    default_flow_style=False,
                    allow_unicode=True,
                    sort_keys=False
                )
                logger.debug(f"Saved YAML to: {file_path}")
            except yaml.YAMLError as e:
                logger.error(f"Error saving YAML file {file_path}: {e}")
                raise

    @staticmethod
    def load_config_yaml(file_path: Path) -> Dict[str, Any]:
        """
        Load configuration YAML with datetime parsing.

        Args:
            file_path: Path to config YAML file

        Returns:
            Parsed configuration

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If required fields are missing
        """
        data = YAMLService.load_yaml(file_path)

        # Parse datetime strings
        datetime_fields = ['created_at', 'not_before', 'not_after']
        for field in datetime_fields:
            if field in data and isinstance(data[field], str):
                try:
                    data[field] = datetime.fromisoformat(data[field].replace('Z', '+00:00'))
                except ValueError as e:
                    logger.warning(f"Error parsing datetime field {field}: {e}")

        return data

    @staticmethod
    def save_config_yaml(file_path: Path, data: Dict[str, Any]) -> None:
        """
        Save configuration to YAML with datetime and Enum formatting.

        Args:
            file_path: Path to save config YAML
            data: Configuration data

        Raises:
            yaml.YAMLError: If data cannot be serialized
        """
        # Convert datetime and Enum objects to appropriate formats
        formatted_data = {}
        for key, value in data.items():
            if isinstance(value, datetime):
                formatted_data[key] = value.isoformat()
            elif isinstance(value, Enum):
                formatted_data[key] = value.value
            elif isinstance(value, dict):
                formatted_data[key] = YAMLService._format_nested_dict(value)
            elif isinstance(value, list):
                formatted_data[key] = [
                    YAMLService._format_nested_dict(item) if isinstance(item, dict)
                    else item.value if isinstance(item, Enum)
                    else item
                    for item in value
                ]
            else:
                formatted_data[key] = value

        YAMLService.save_yaml(file_path, formatted_data)

    @staticmethod
    def _format_nested_dict(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recursively format nested dictionaries, converting datetime and Enum objects.

        Args:
            data: Dictionary to format

        Returns:
            Formatted dictionary
        """
        formatted = {}
        for key, value in data.items():
            if isinstance(value, datetime):
                formatted[key] = value.isoformat()
            elif isinstance(value, Enum):
                formatted[key] = value.value
            elif isinstance(value, dict):
                formatted[key] = YAMLService._format_nested_dict(value)
            elif isinstance(value, list):
                formatted[key] = [
                    YAMLService._format_nested_dict(item) if isinstance(item, dict)
                    else item.value if isinstance(item, Enum)
                    else item
                    for item in value
                ]
            else:
                formatted[key] = value
        return formatted
