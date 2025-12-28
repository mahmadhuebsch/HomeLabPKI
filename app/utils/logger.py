"""Logging configuration."""

import logging
from pathlib import Path
from typing import Optional
from app.models.config import AppConfig


def setup_logger(config: Optional[AppConfig] = None) -> logging.Logger:
    """
    Configure application logger.

    Args:
        config: Application configuration

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger("yacertmanager")

    # Prevent duplicate handlers
    if logger.handlers:
        return logger

    # Set level
    level = logging.INFO
    if config and hasattr(config, 'logging'):
        level = getattr(logging, config.logging.level, logging.INFO)

    logger.setLevel(level)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(
        '%(levelname)s: %(message)s'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # File handler (if config provided)
    if config and hasattr(config, 'logging'):
        log_file = Path(config.logging.file)
        log_file.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_formatter = logging.Formatter(config.logging.format)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    return logger
