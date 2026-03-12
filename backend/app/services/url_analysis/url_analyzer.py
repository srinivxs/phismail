"""
PhisMail — URL Analyzer
Structural analysis and obfuscation detection for URLs.
"""

import re
import math
from urllib.parse import urlparse, unquote
from typing import Optional
import tldextract

from app.core.security import URL_SHORTENERS, BRAND_KEYWORDS
from app.core.logging import get_logger

logger = get_logger(__name__)


class UrlAnalysisResult:
    """Result of URL structural analysis."""

    def __init__(self, url: str):
        self.url = url
        self.domain: Optional[str] = None
        self.tld: Optional[str] = None

        # Structural features
        self.url_length: int = len(url)
        self.num_dots: int = 0
        self.num_subdomains: int = 0
        self.num_hyphens: int = 0
        self.num_special_chars: int = 0
        self.contains_ip: bool = False
        self.contains_at_symbol: bool = False
        self.num_query_parameters: int = 0
        self.entropy_score: float = 0.0
        self.num_fragments: int = 0
        self.has_https: bool = False
        self.is_shortened: bool = False

        # Obfuscation indicators
        self.percent_encoding_count: int = 0
        self.hex_encoding_count: int = 0
        self.double_slash_redirect: bool = False
        self.encoded_characters_ratio: float = 0.0
        self.username_in_url: bool = False
        self.mixed_case_domain: bool = False
        self.long_query_string: bool = False

        # Brand signals
        self.brand_keyword_present: bool = False
        self.detected_brand: Optional[str] = None


def analyze_url(url: str) -> UrlAnalysisResult:
    """Perform structural and obfuscation analysis on a URL."""

    result = UrlAnalysisResult(url)
    parsed = urlparse(url)
    extracted = tldextract.extract(url)

    # Domain info
    result.domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
    result.tld = f".{extracted.suffix}" if extracted.suffix else None
    result.has_https = parsed.scheme == "https"

    # Structural features
    result.num_dots = url.count(".")
    result.num_hyphens = url.count("-")
    result.num_special_chars = len(re.findall(r"[^a-zA-Z0-9./:-]", url))
    result.num_subdomains = len(extracted.subdomain.split(".")) if extracted.subdomain else 0
    result.contains_at_symbol = "@" in url
    result.num_fragments = url.count("#")

    # Query parameters
    if parsed.query:
        result.num_query_parameters = parsed.query.count("&") + 1
        result.long_query_string = len(parsed.query) > 100

    # IP-based URL detection
    ip_pattern = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    result.contains_ip = bool(ip_pattern.search(parsed.netloc))

    # Entropy score
    result.entropy_score = _calculate_entropy(url)

    # URL shortener detection
    hostname = parsed.hostname or ""
    result.is_shortened = hostname.lower() in URL_SHORTENERS

    # --- Obfuscation detection ---

    # Percent encoding
    result.percent_encoding_count = len(re.findall(r"%[0-9a-fA-F]{2}", url))
    decoded = unquote(url)
    if len(url) > 0:
        result.encoded_characters_ratio = (len(url) - len(decoded)) / len(url) if decoded != url else 0.0

    # Hex encoding
    result.hex_encoding_count = len(re.findall(r"0x[0-9a-fA-F]+", url))

    # Double slash redirect
    result.double_slash_redirect = "//" in parsed.path

    # Username in URL (user@domain)
    result.username_in_url = "@" in (parsed.netloc or "")

    # Mixed case domain
    if parsed.hostname:
        result.mixed_case_domain = parsed.hostname != parsed.hostname.lower()

    # --- Brand impersonation signals ---
    url_lower = url.lower()
    for brand in BRAND_KEYWORDS:
        if brand in url_lower:
            result.brand_keyword_present = True
            result.detected_brand = brand
            break

    return result


def _calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""

    if not text:
        return 0.0

    char_counts = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1

    length = len(text)
    entropy = 0.0
    for count in char_counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return round(entropy, 4)
