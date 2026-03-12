"""
PhisMail — Artifact Store
Unified facade over storage backends for all artifact types.
"""

import hashlib
from pathlib import Path

from app.core.config import get_settings
from app.core.logging import get_logger
from app.storage.email_store import EmailStore

logger = get_logger(__name__)
settings = get_settings()


def _normalize_url(url: str) -> str:
    """Lightweight URL normalization for hashing (lowercase + strip)."""
    return url.strip().lower().rstrip("/")


class ArtifactStore:
    """
    High-level store that wraps individual storage backends.

    Currently supports email artifacts; additional backends (e.g. URL
    screenshots, PCAP captures) can be added here in the future.
    """

    def __init__(self) -> None:
        self._email_store = EmailStore()
        logger.debug("artifact_store_initialized")

    # ------------------------------------------------------------------
    # Email artifacts
    # ------------------------------------------------------------------

    def store_email(self, content: bytes, filename: str) -> tuple[str, str]:
        """
        Persist an .eml file and return its storage path and hash.

        Delegates to :class:`~app.storage.email_store.EmailStore`.

        Returns:
            (file_path, sha256_hash)
        """
        return self._email_store.save(content, filename)

    def get_email_path(self, stored_filename: str) -> str:
        """Return the absolute path for a previously stored email file."""
        return self._email_store.get_path(stored_filename)

    # ------------------------------------------------------------------
    # URL artifacts
    # ------------------------------------------------------------------

    def compute_url_artifact_id(self, url: str) -> str:
        """
        Compute a deterministic artifact ID for a URL.

        The ID is the SHA-256 hex digest of the normalized URL, suitable
        for deduplication and lookup.
        """
        normalized = _normalize_url(url)
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------
    # Generic helpers
    # ------------------------------------------------------------------

    def artifact_exists(self, artifact_hash: str) -> bool:
        """
        Check whether a stored artifact file exists for *artifact_hash*.

        Uses the EmailStore to probe whether a file whose path contains the
        given hash prefix is present on disk.
        """
        path = self._email_store.get_path(artifact_hash)
        return self._email_store.exists(path)
