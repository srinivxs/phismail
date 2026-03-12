"""
PhisMail — Email Parser Service
Parses .eml files to extract structured email components.
"""

import email
import hashlib
import re
from email import policy
from email.parser import BytesParser
from typing import Dict, List, Optional, Any
from bs4 import BeautifulSoup

from app.core.logging import get_logger

logger = get_logger(__name__)


class ParsedEmailResult:
    """Structured result from email parsing."""

    def __init__(self):
        self.sender: Optional[str] = None
        self.reply_to: Optional[str] = None
        self.return_path: Optional[str] = None
        self.subject: Optional[str] = None
        self.body_text: Optional[str] = None
        self.body_html: Optional[str] = None
        self.headers: Dict[str, Any] = {}
        self.attachments: List[Dict[str, Any]] = []
        self.urls: List[str] = []
        self.originating_ip: Optional[str] = None


def parse_eml_file(file_path: str) -> ParsedEmailResult:
    """Parse an .eml file and extract all components."""

    with open(file_path, "rb") as f:
        raw_content = f.read()

    return parse_eml_bytes(raw_content)


def parse_eml_bytes(raw_content: bytes) -> ParsedEmailResult:
    """Parse raw email bytes into structured components."""

    result = ParsedEmailResult()
    msg = BytesParser(policy=policy.default).parsebytes(raw_content)

    # Extract headers
    result.sender = msg.get("From", "")
    result.reply_to = msg.get("Reply-To", "")
    result.return_path = msg.get("Return-Path", "")
    result.subject = msg.get("Subject", "")

    # Store all headers
    result.headers = {key: str(value) for key, value in msg.items()}

    # Extract originating IP from Received headers
    result.originating_ip = _extract_originating_ip(msg)

    # Extract body
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            if "attachment" in content_disposition:
                # Process attachment metadata
                attachment_meta = _extract_attachment_meta(part)
                result.attachments.append(attachment_meta)
            elif content_type == "text/plain" and not result.body_text:
                try:
                    result.body_text = part.get_content()
                except Exception:
                    result.body_text = ""
            elif content_type == "text/html" and not result.body_html:
                try:
                    result.body_html = part.get_content()
                except Exception:
                    result.body_html = ""
    else:
        content_type = msg.get_content_type()
        try:
            content = msg.get_content()
        except Exception:
            content = ""

        if content_type == "text/html":
            result.body_html = content
        else:
            result.body_text = content

    # Extract URLs from body
    result.urls = extract_urls_from_content(result.body_text, result.body_html)

    return result


def _extract_originating_ip(msg) -> Optional[str]:
    """Extract the originating IP from Received headers."""

    ip_pattern = re.compile(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]")
    received_headers = msg.get_all("Received", [])

    for header in reversed(received_headers):
        header_str = str(header)
        match = ip_pattern.search(header_str)
        if match:
            ip = match.group(1)
            # Skip private/local IPs
            if not ip.startswith(("10.", "172.", "192.168.", "127.")):
                return ip
    return None


def _extract_attachment_meta(part) -> Dict[str, Any]:
    """Extract attachment metadata without executing the attachment."""

    filename = part.get_filename() or "unknown"
    content_type = part.get_content_type()

    try:
        payload = part.get_payload(decode=True) or b""
        size = len(payload)
        file_hash = hashlib.sha256(payload).hexdigest()
    except Exception:
        size = 0
        file_hash = ""

    return {
        "filename": filename,
        "content_type": content_type,
        "size": size,
        "sha256": file_hash,
    }


def extract_urls_from_content(
    body_text: Optional[str],
    body_html: Optional[str],
) -> List[str]:
    """Extract URLs from email body text and HTML."""

    urls = set()

    # URL regex pattern
    url_pattern = re.compile(
        r"https?://[^\s<>\"'\)\]\}]+",
        re.IGNORECASE,
    )

    # Extract from plain text
    if body_text:
        for match in url_pattern.finditer(body_text):
            urls.add(match.group(0).rstrip(".,;:!?)]}"))

    # Extract from HTML (href attributes)
    if body_html:
        try:
            soup = BeautifulSoup(body_html, "html.parser")
            for tag in soup.find_all(["a", "link", "script", "img", "iframe"]):
                href = tag.get("href") or tag.get("src")
                if href and href.startswith(("http://", "https://")):
                    urls.add(href)
        except Exception:
            pass

        # Also find URLs in raw HTML text
        for match in url_pattern.finditer(body_html):
            urls.add(match.group(0).rstrip(".,;:!?)]}"))

    return list(urls)
