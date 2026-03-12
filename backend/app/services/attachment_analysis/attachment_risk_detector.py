"""
PhisMail — Attachment Risk Detector
Analyzes attachment metadata for risky file types (never executes files).
"""

import os
from typing import List, Dict, Any

from app.core.security import EXECUTABLE_EXTENSIONS, MACRO_EXTENSIONS, ARCHIVE_EXTENSIONS
from app.core.logging import get_logger

logger = get_logger(__name__)


class AttachmentRiskResult:
    """Result of attachment risk analysis."""

    def __init__(self):
        self.attachment_count: int = 0
        self.has_executable: bool = False
        self.has_script: bool = False
        self.has_macro_document: bool = False
        self.has_archive: bool = False
        self.double_extension_detected: bool = False
        self.archive_with_executable: bool = False
        self.mime_mismatch_detected: bool = False
        self.risky_attachments: List[Dict[str, Any]] = []
        self.risk_score: float = 0.0


def analyze_attachments(attachments: List[Dict[str, Any]]) -> AttachmentRiskResult:
    """Analyze attachment metadata for indicators of risk."""

    result = AttachmentRiskResult()
    result.attachment_count = len(attachments)

    if not attachments:
        return result

    for attachment in attachments:
        filename = attachment.get("filename", "").lower()
        content_type = attachment.get("content_type", "").lower()
        size = attachment.get("size", 0)

        risks = []

        # Check for executable extensions
        _, ext = os.path.splitext(filename)
        if ext in EXECUTABLE_EXTENSIONS:
            result.has_executable = True
            risks.append("executable")

        # Check for script extensions
        if ext in [".js", ".vbs", ".ps1", ".bat", ".cmd", ".wsf"]:
            result.has_script = True
            risks.append("script")

        # Check for macro documents
        if ext in MACRO_EXTENSIONS:
            result.has_macro_document = True
            risks.append("macro_document")

        # Check for archives (could contain executables)
        if ext in ARCHIVE_EXTENSIONS:
            result.has_archive = True
            risks.append("archive")

        # Double extension detection (e.g., "document.pdf.exe")
        name_without_ext = filename.rsplit(".", 1)[0] if "." in filename else filename
        if "." in name_without_ext:
            second_ext = os.path.splitext(name_without_ext)[1]
            if second_ext and ext in EXECUTABLE_EXTENSIONS:
                result.double_extension_detected = True
                risks.append("double_extension")

        # MIME type mismatch detection
        if _detect_mime_mismatch(ext, content_type):
            result.mime_mismatch_detected = True
            risks.append("mime_mismatch")

        if risks:
            result.risky_attachments.append({
                "filename": attachment.get("filename", ""),
                "content_type": content_type,
                "size": size,
                "sha256": attachment.get("sha256", ""),
                "risks": risks,
            })

    # Calculate composite risk score
    risk_factors = [
        result.has_executable * 0.35,
        result.has_script * 0.25,
        result.has_macro_document * 0.2,
        result.double_extension_detected * 0.3,
        result.mime_mismatch_detected * 0.15,
        result.has_archive * 0.1,
    ]
    result.risk_score = min(sum(risk_factors), 1.0)

    return result


def _detect_mime_mismatch(extension: str, content_type: str) -> bool:
    """Check if the file extension doesn't match the declared MIME type."""

    expected_mimes = {
        ".pdf": ["application/pdf"],
        ".doc": ["application/msword"],
        ".docx": ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"],
        ".xls": ["application/vnd.ms-excel"],
        ".xlsx": ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"],
        ".zip": ["application/zip", "application/x-zip-compressed"],
        ".exe": ["application/x-msdownload", "application/x-executable"],
        ".jpg": ["image/jpeg"],
        ".png": ["image/png"],
    }

    if extension in expected_mimes:
        return content_type not in expected_mimes[extension]

    return False
