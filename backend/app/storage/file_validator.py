"""
PhisMail — File Upload Validator
MIME-type and size validation for uploaded email artifacts.
"""

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()

# Accepted MIME types for .eml uploads
ALLOWED_MIME_TYPES: set[str] = {
    "message/rfc822",
    "application/octet-stream",
    "text/plain",
}

# Hard-coded upper bound; also enforced via settings at the API layer
MAX_FILE_SIZE_BYTES: int = 5 * 1024 * 1024  # 5 MB


class FileValidationError(Exception):
    """Raised when an uploaded file fails validation checks."""


def validate_upload(filename: str, content: bytes) -> None:
    """
    Validate an uploaded file for size, extension, and MIME type.

    Raises:
        FileValidationError: if any validation check fails.
    """
    # 1. Size check
    if len(content) > MAX_FILE_SIZE_BYTES:
        max_mb = MAX_FILE_SIZE_BYTES / (1024 * 1024)
        raise FileValidationError(
            f"File size {len(content)} bytes exceeds the maximum of "
            f"{max_mb:.0f} MB ({MAX_FILE_SIZE_BYTES} bytes)"
        )

    # 2. Extension check
    if not filename.lower().endswith(".eml"):
        raise FileValidationError(
            f"Only .eml files are accepted; received '{filename}'"
        )

    # 3. MIME type check via python-magic (optional — skip if unavailable)
    detected_mime = get_file_mime(content)
    if detected_mime not in ALLOWED_MIME_TYPES:
        raise FileValidationError(
            f"Detected MIME type '{detected_mime}' is not permitted. "
            f"Allowed types: {', '.join(sorted(ALLOWED_MIME_TYPES))}"
        )


def get_file_mime(content: bytes) -> str:
    """
    Detect the MIME type of *content* using python-magic.

    Falls back to 'application/octet-stream' if python-magic is not
    installed or detection fails.
    """
    try:
        import magic  # type: ignore[import]
        return magic.from_buffer(content, mime=True)
    except ImportError:
        logger.warning(
            "python_magic_unavailable",
            detail="python-magic is not installed; skipping MIME type detection",
        )
        return "application/octet-stream"
    except Exception as exc:
        logger.warning(
            "mime_detection_error",
            error=str(exc),
            detail="MIME detection failed; falling back to application/octet-stream",
        )
        return "application/octet-stream"
