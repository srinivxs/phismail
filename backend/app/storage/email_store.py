"""
PhisMail — Email File Store
Persistent storage for uploaded .eml files with SHA-256 based naming.
"""

import os
import re
import hashlib
from pathlib import Path

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()

# Characters allowed in sanitized filenames
_SAFE_FILENAME_RE = re.compile(r"[^a-zA-Z0-9.\-_]")


def _sanitize_filename(filename: str) -> str:
    """Replace any characters outside [a-zA-Z0-9 . - _] with underscores."""
    return _SAFE_FILENAME_RE.sub("_", filename)


class EmailStore:
    """Simple on-disk store for .eml files, keyed by a SHA-256 prefix."""

    def __init__(self, storage_path: str | None = None) -> None:
        base = storage_path or settings.storage_path
        self._storage_dir = Path(base) / "emails"
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        logger.debug(
            "email_store_initialized",
            storage_dir=str(self._storage_dir),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def save(self, content: bytes, filename: str) -> tuple[str, str]:
        """
        Persist *content* to disk.

        The stored file is named ``{sha256[:16]}_{sanitized_filename}``
        to avoid collisions and path-traversal issues.

        Returns:
            (file_path, sha256_hash) where *file_path* is the absolute
            path of the saved file.
        """
        sha256_hash = hashlib.sha256(content).hexdigest()
        safe_name = _sanitize_filename(filename)
        stored_filename = f"{sha256_hash[:16]}_{safe_name}"
        file_path = str(self._storage_dir / stored_filename)

        with open(file_path, "wb") as fh:
            fh.write(content)

        logger.debug(
            "email_stored",
            file_path=file_path,
            size_bytes=len(content),
            sha256=sha256_hash,
        )
        return file_path, sha256_hash

    def get_path(self, stored_filename: str) -> str:
        """Return the absolute path for a previously stored filename."""
        return str(self._storage_dir / stored_filename)

    def exists(self, file_path: str) -> bool:
        """Return True if the file at *file_path* exists on disk."""
        return os.path.isfile(file_path)

    def delete(self, file_path: str) -> bool:
        """
        Delete the file at *file_path*.

        Returns True if the file was deleted, False if it did not exist or
        deletion failed.
        """
        try:
            os.remove(file_path)
            logger.debug("email_deleted", file_path=file_path)
            return True
        except FileNotFoundError:
            logger.debug("email_delete_not_found", file_path=file_path)
            return False
        except OSError as exc:
            logger.warning(
                "email_delete_error",
                file_path=file_path,
                error=str(exc),
            )
            return False
