"""
PhisMail — Security Configuration
Rate limiting, file validation constraints, and security helpers.
"""

import hashlib
from typing import Optional
from app.core.config import get_settings

settings = get_settings()

# =============================================================================
# Brand Keywords for Impersonation Detection
# =============================================================================
BRAND_KEYWORDS = [
    "paypal", "microsoft", "apple", "google", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "twitter", "linkedin",
    "dropbox", "adobe", "chase", "wellsfargo", "bankofamerica",
    "citibank", "hsbc", "barclays", "usps", "fedex", "dhl",
    "irs", "hmrc", "gov", "admin", "support", "security",
    "verify", "confirm", "update", "suspend", "locked", "urgent",
]

# =============================================================================
# Suspicious TLDs
# =============================================================================
SUSPICIOUS_TLDS = [
    ".ru", ".cn", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".xyz", ".top", ".buzz", ".club", ".work", ".date",
    ".bid", ".stream", ".click", ".link", ".info", ".pw",
]

# =============================================================================
# Risky Attachment Extensions
# =============================================================================
EXECUTABLE_EXTENSIONS = [
    ".exe", ".msi", ".bat", ".cmd", ".com", ".scr", ".pif",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1",
    ".psm1", ".reg",
]

MACRO_EXTENSIONS = [
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm",
]

ARCHIVE_EXTENSIONS = [
    ".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".img",
]

RISKY_EXTENSIONS = EXECUTABLE_EXTENSIONS + MACRO_EXTENSIONS + ARCHIVE_EXTENSIONS


# =============================================================================
# URL Shorteners
# =============================================================================
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "j.mp", "rb.gy", "cutt.ly",
    "shorturl.at", "tiny.cc",
]


# =============================================================================
# Hashing Utilities
# =============================================================================
def compute_sha256(data: bytes) -> str:
    """Compute SHA256 hash of binary data."""
    return hashlib.sha256(data).hexdigest()


def compute_url_hash(url: str) -> str:
    """Compute normalized hash of a URL for dedup."""
    normalized = url.strip().lower().rstrip("/")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()
