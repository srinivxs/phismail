"""
PhisMail — Attachment Metadata Handler
Dedicated module for extracting and analysing email attachment metadata,
expanding the basic extraction in parser.py.
"""

import hashlib
from dataclasses import dataclass, field
from email.message import Message
from typing import List, Optional

from app.core.logging import get_logger
from app.core.security import (
    ARCHIVE_EXTENSIONS,
    EXECUTABLE_EXTENSIONS,
    MACRO_EXTENSIONS,
)

logger = get_logger(__name__)

# Script extensions that are not already in EXECUTABLE_EXTENSIONS
SCRIPT_EXTENSIONS = [
    ".py", ".rb", ".pl", ".sh", ".bash", ".zsh", ".fish",
    ".php", ".asp", ".aspx", ".jsp",
]


@dataclass
class AttachmentMetadata:
    """Structured metadata for a single email attachment."""

    filename: str
    content_type: str
    size: int
    sha256: str
    extension: str
    is_inline: bool
    content_id: Optional[str]


def extract_attachments(msg: Message) -> List[AttachmentMetadata]:
    """Extract attachment metadata from all parts of an email message.

    Iterates every MIME part of *msg* and returns an
    :class:`AttachmentMetadata` record for each part that is not
    ``text/plain`` or ``text/html``.  The SHA-256 digest is computed
    from the decoded payload bytes so it can be used for deduplication
    or downstream reputation lookups.

    Args:
        msg: A :class:`email.message.Message` (or compatible) object
             produced by the standard-library email parser.

    Returns:
        A list of :class:`AttachmentMetadata` instances, one per
        qualifying part.  Returns an empty list when *msg* has no
        attachable parts.
    """

    attachments: List[AttachmentMetadata] = []

    for part in msg.walk():
        content_type = part.get_content_type()

        # Skip the body parts we do not treat as attachments
        if content_type in ("text/plain", "text/html", "multipart/mixed",
                             "multipart/alternative", "multipart/related"):
            continue

        # Derive filename and extension
        filename: str = part.get_filename() or ""
        if not filename:
            # Fall back to a name derived from the Content-Type subtype
            subtype = part.get_content_subtype()
            filename = f"unnamed.{subtype}" if subtype else "unnamed"

        extension = ""
        if "." in filename:
            extension = "." + filename.rsplit(".", 1)[-1].lower()

        # Compute hash from decoded payload
        try:
            payload_bytes: bytes = part.get_payload(decode=True) or b""
            size = len(payload_bytes)
            sha256 = hashlib.sha256(payload_bytes).hexdigest()
        except Exception as exc:
            logger.warning(
                "attachment_hash_failed",
                filename=filename,
                error=str(exc),
            )
            size = 0
            sha256 = ""

        # Inline vs attachment disposition
        content_disposition = str(part.get("Content-Disposition", "")).lower()
        is_inline = "inline" in content_disposition

        content_id: Optional[str] = part.get("Content-ID")
        if content_id:
            # Strip surrounding angle brackets if present
            content_id = content_id.strip("<>")

        attachments.append(
            AttachmentMetadata(
                filename=filename,
                content_type=content_type,
                size=size,
                sha256=sha256,
                extension=extension,
                is_inline=is_inline,
                content_id=content_id,
            )
        )

    return attachments


def get_attachment_risk_summary(
    attachments: List[AttachmentMetadata],
) -> dict:
    """Produce a risk-oriented summary of a list of attachment metadata records.

    Checks each attachment's extension against the lists imported from
    :mod:`app.core.security` to flag executable, script, macro-enabled,
    and archive files.

    Args:
        attachments: A list of :class:`AttachmentMetadata` objects,
                     typically the return value of :func:`extract_attachments`.

    Returns:
        A dictionary with the following keys:

        * ``total_count`` – int: total number of attachments.
        * ``has_executable`` – bool: at least one executable extension found.
        * ``has_script`` – bool: at least one script extension found.
        * ``has_macro`` – bool: at least one macro-enabled document found.
        * ``has_archive`` – bool: at least one archive extension found.
        * ``filenames`` – list[str]: all attachment filenames.
        * ``sha256_hashes`` – list[str]: all non-empty SHA-256 digests.
    """

    has_executable = False
    has_script = False
    has_macro = False
    has_archive = False
    filenames: List[str] = []
    sha256_hashes: List[str] = []

    for att in attachments:
        ext = att.extension.lower()

        if ext in EXECUTABLE_EXTENSIONS:
            has_executable = True
        if ext in SCRIPT_EXTENSIONS:
            has_script = True
        if ext in MACRO_EXTENSIONS:
            has_macro = True
        if ext in ARCHIVE_EXTENSIONS:
            has_archive = True

        filenames.append(att.filename)
        if att.sha256:
            sha256_hashes.append(att.sha256)

    return {
        "total_count": len(attachments),
        "has_executable": has_executable,
        "has_script": has_script,
        "has_macro": has_macro,
        "has_archive": has_archive,
        "filenames": filenames,
        "sha256_hashes": sha256_hashes,
    }
