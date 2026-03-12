"""
PhisMail — Homograph Detector
Detects Unicode homograph attacks and IDN domain spoofing.
"""

import re
from typing import Optional, List, Tuple

from app.core.security import BRAND_KEYWORDS
from app.core.logging import get_logger

logger = get_logger(__name__)

# Common confusable character mappings (subset)
CONFUSABLE_MAP = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y",
    "х": "x", "ѕ": "s", "і": "i", "ј": "j", "ᴀ": "a", "ᴄ": "c",
    "ᴅ": "d", "ᴇ": "e", "ɡ": "g", "ʜ": "h", "ᴋ": "k", "ʟ": "l",
    "ᴍ": "m", "ɴ": "n", "ᴏ": "o", "ᴘ": "p", "ǫ": "q", "ʀ": "r",
    "ꜱ": "s", "ᴛ": "t", "ᴜ": "u", "ᴠ": "v", "ᴡ": "w", "ᴢ": "z",
    "ⅰ": "i", "ⅱ": "ii", "ℓ": "l", "ⅿ": "m", "ℕ": "n",
    "ℙ": "p", "ℚ": "q", "ℝ": "r", "ℤ": "z",
    "０": "0", "１": "1", "２": "2", "３": "3", "４": "4",
    "５": "5", "６": "6", "７": "7", "８": "8", "９": "9",
}


class HomographResult:
    """Result of homograph detection."""

    def __init__(self):
        self.is_homograph: bool = False
        self.is_idn: bool = False
        self.punycode: Optional[str] = None
        self.normalized_domain: Optional[str] = None
        self.confusable_chars: List[Tuple[str, str]] = []
        self.matched_brand: Optional[str] = None
        self.similarity_score: float = 0.0


def detect_homograph(domain: str) -> HomographResult:
    """Detect if a domain uses homograph characters to impersonate a brand."""

    result = HomographResult()

    # Check if it's an IDN (Internationalized Domain Name)
    if any(ord(c) > 127 for c in domain):
        result.is_idn = True
        try:
            result.punycode = domain.encode("idna").decode("ascii")
        except Exception:
            result.punycode = None

    # Normalize domain by replacing confusable characters
    normalized = _normalize_confusables(domain)
    result.normalized_domain = normalized

    # Find confusable characters used
    for i, char in enumerate(domain):
        if char in CONFUSABLE_MAP:
            result.confusable_chars.append((char, CONFUSABLE_MAP[char]))

    if result.confusable_chars:
        result.is_homograph = True

    # Check if normalized domain matches any brand
    domain_lower = normalized.lower()
    for brand in BRAND_KEYWORDS:
        if brand in domain_lower:
            result.matched_brand = brand
            result.similarity_score = _calculate_similarity(domain_lower, brand)
            break

    # Check for typosquatting (character swaps, additions, omissions)
    for brand in BRAND_KEYWORDS:
        sim = _calculate_similarity(domain.lower().split(".")[0], brand)
        if sim > 0.75 and sim < 1.0:
            result.matched_brand = brand
            result.similarity_score = sim
            result.is_homograph = True
            break

    return result


def _normalize_confusables(text: str) -> str:
    """Replace confusable Unicode characters with their ASCII equivalents."""

    result = []
    for char in text:
        if char in CONFUSABLE_MAP:
            result.append(CONFUSABLE_MAP[char])
        else:
            result.append(char)
    return "".join(result)


def _calculate_similarity(s1: str, s2: str) -> float:
    """Calculate Levenshtein-based similarity between two strings."""

    if not s1 or not s2:
        return 0.0

    len1, len2 = len(s1), len(s2)
    matrix = [[0] * (len2 + 1) for _ in range(len1 + 1)]

    for i in range(len1 + 1):
        matrix[i][0] = i
    for j in range(len2 + 1):
        matrix[0][j] = j

    for i in range(1, len1 + 1):
        for j in range(1, len2 + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            matrix[i][j] = min(
                matrix[i - 1][j] + 1,
                matrix[i][j - 1] + 1,
                matrix[i - 1][j - 1] + cost,
            )

    distance = matrix[len1][len2]
    max_len = max(len1, len2)
    return 1.0 - (distance / max_len) if max_len > 0 else 0.0
