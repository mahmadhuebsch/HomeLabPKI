"""File system utilities."""

import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger("homelabpki")


class FileUtils:
    """Utility class for file operations."""

    @staticmethod
    def ensure_directory(path: Path) -> None:
        """
        Ensure directory exists, create if not.

        Args:
            path: Directory path to ensure
        """
        path.mkdir(parents=True, exist_ok=True)
        logger.debug(f"Ensured directory exists: {path}")

    @staticmethod
    def delete_directory(path: Path, ignore_errors: bool = False) -> None:
        """
        Delete directory and all contents.

        Args:
            path: Directory path to delete
            ignore_errors: Whether to ignore errors during deletion
        """
        if path.exists():
            shutil.rmtree(path, ignore_errors=ignore_errors)
            logger.info(f"Deleted directory: {path}")

    @staticmethod
    def move_to_trash(path: Path) -> Path:
        """
        Move directory to _trash folder at same level with timestamp.

        Instead of permanently deleting, moves the directory to a _trash
        subdirectory in the parent folder with a timestamp suffix to avoid
        naming conflicts.

        Args:
            path: Directory path to move to trash

        Returns:
            Path to the trashed directory

        Raises:
            ValueError: If path does not exist
        """
        if not path.exists():
            raise ValueError(f"Path not found: {path}")

        trash_dir = path.parent / "_trash"
        trash_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        dest = trash_dir / f"{path.name}_{timestamp}"
        shutil.move(str(path), str(dest))
        logger.info(f"Moved to trash: {path} -> {dest}")
        return dest

    @staticmethod
    def copy_file(src: Path, dst: Path) -> None:
        """
        Copy file from source to destination.

        Args:
            src: Source file path
            dst: Destination file path
        """
        FileUtils.ensure_directory(dst.parent)
        shutil.copy2(src, dst)
        logger.debug(f"Copied file: {src} -> {dst}")

    @staticmethod
    def read_file(path: Path) -> str:
        """
        Read file contents as string.

        Args:
            path: File path to read

        Returns:
            File contents as string
        """
        with open(path, "r", encoding="utf-8") as f:
            return f.read()

    @staticmethod
    def read_binary_file(path: Path) -> bytes:
        """
        Read file contents as bytes.

        Args:
            path: File path to read

        Returns:
            File contents as bytes
        """
        with open(path, "rb") as f:
            return f.read()

    @staticmethod
    def write_file(path: Path, content: str) -> None:
        """
        Write string content to file.

        Args:
            path: File path to write
            content: Content to write
        """
        FileUtils.ensure_directory(path.parent)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        logger.debug(f"Wrote file: {path}")

    @staticmethod
    def write_binary_file(path: Path, content: bytes) -> None:
        """
        Write binary content to file.

        Args:
            path: File path to write
            content: Binary content to write
        """
        FileUtils.ensure_directory(path.parent)
        with open(path, "wb") as f:
            f.write(content)
        logger.debug(f"Wrote binary file: {path}")

    @staticmethod
    def list_directories(path: Path) -> list[Path]:
        """
        List all directories in given path, excluding _trash folders.

        Args:
            path: Path to search

        Returns:
            List of directory paths (excludes _trash directories)
        """
        if not path.exists():
            return []
        return [p for p in path.iterdir() if p.is_dir() and p.name != "_trash"]

    @staticmethod
    def list_files(path: Path, pattern: str = "*") -> list[Path]:
        """
        List all files matching pattern in given path.

        Args:
            path: Path to search
            pattern: Glob pattern to match

        Returns:
            List of file paths
        """
        if not path.exists():
            return []
        return list(path.glob(pattern))
