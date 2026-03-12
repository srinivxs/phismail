"""
PhisMail — Input Validation Utilities
URL and file validation helpers for artifact submission.
"""

import hashlib
import re
from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl


def validate_url(url: str) -> tuple[bool, str]:
    """
    Validate URL format.

    Checks:
    - Must use http or https scheme
    - Host must not be empty
    - Total length must not exceed 2048 characters

    Returns:
        (is_valid, error_message) — error_message is empty string on success
    """
    if len(url) > 2048:
        return False, f"URL exceeds maximum length of 2048 characters (got {len(url)})"

    try:
        parsed = urlparse(url)
    except Exception as exc:
        return False, f"URL parse error: {exc}"

    if parsed.scheme not in ("http", "https"):
        return False, f"URL scheme must be 'http' or 'https', got '{parsed.scheme}'"

    if not parsed.netloc or not parsed.hostname:
        return False, "URL host must not be empty"

    return True, ""


def validate_eml_file(
    filename: str,
    content: bytes,
    max_size_bytes: int,
) -> tuple[bool, str]:
    """
    Validate an uploaded .eml file.

    Checks:
    - File extension must be .eml
    - File size must not exceed max_size_bytes
    - First 512 bytes must contain recognisable email headers
      (From:, Return-Path:, or MIME-Version:)

    Returns:
        (is_valid, error_message) — error_message is empty string on success
    """
    if not filename.lower().endswith(".eml"):
        return False, f"Only .eml files are accepted, got '{filename}'"

    if len(content) > max_size_bytes:
        max_mb = max_size_bytes / (1024 * 1024)
        return False, f"File size exceeds maximum of {max_mb:.0f} MB"

    # Heuristic MIME check: look for common email headers in the first 512 bytes
    header_sample = content[:512]
    try:
        header_text = header_sample.decode("utf-8", errors="replace")
    except Exception:
        header_text = header_sample.decode("latin-1", errors="replace")

    email_markers = ("From:", "Return-Path:", "MIME-Version:")
    if not any(marker in header_text for marker in email_markers):
        return False, (
            "File does not appear to be a valid .eml: "
            "no recognised email headers (From:, Return-Path:, MIME-Version:) "
            "found in first 512 bytes"
        )

    return True, ""


def compute_file_hash(content: bytes) -> str:
    """Return the SHA-256 hex digest of raw file bytes."""
    return hashlib.sha256(content).hexdigest()


def compute_url_hash(url: str) -> str:
    """Return the SHA-256 hex digest of the normalized URL string."""
    normalized = normalize_url(url)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def normalize_url(url: str) -> str:
    """
    Normalize a URL for consistent deduplication.

    Steps applied:
    - Lowercase scheme and host
    - Strip trailing slash from path (unless path is just '/')
    - Remove fragment
    - Sort query parameters alphabetically
    """
    try:
        parsed = urlparse(url.strip())
    except Exception:
        return url.strip().lower()

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip("/") or "/"
    # Sort query params for deterministic representation
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    # Drop fragment entirely
    normalized = urlunparse((scheme, netloc, path, parsed.params, query, ""))
    return normalized
