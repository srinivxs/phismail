"""
PhisMail — URL Analysis Utilities
Helpers for URL parsing, entropy calculation, and component extraction.
"""

import math
import ipaddress
from urllib.parse import urlparse, unquote

import tldextract


def extract_domain(url: str) -> str:
    """
    Return the registered domain (e.g. 'evil.com') from a full URL.

    Examples:
        'http://sub.evil.com/path' -> 'evil.com'
        'https://www.google.com'   -> 'google.com'
    """
    extracted = tldextract.extract(url)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return extracted.domain or ""


def extract_subdomain(url: str) -> str:
    """Return the subdomain portion of the URL host."""
    return tldextract.extract(url).subdomain


def extract_tld(url: str) -> str:
    """Return the public suffix / TLD of the URL host."""
    return tldextract.extract(url).suffix


def calculate_entropy(s: str) -> float:
    """
    Calculate the Shannon entropy of a string.

    Returns 0.0 for empty strings.
    """
    if not s:
        return 0.0

    length = len(s)
    freq: dict[str, int] = {}
    for char in s:
        freq[char] = freq.get(char, 0) + 1

    entropy = 0.0
    for count in freq.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def count_special_chars(url: str) -> int:
    """
    Count characters in the URL that are not alphanumeric or in: . / : - _ ~

    These extra characters can be indicators of obfuscation.
    """
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./:-_~")
    return sum(1 for ch in url if ch not in allowed)


def is_ip_address(host: str) -> bool:
    """
    Return True if *host* is a valid IPv4 or IPv6 address (not a hostname).
    """
    # Strip IPv6 brackets if present
    stripped = host.strip("[]")
    try:
        ipaddress.ip_address(stripped)
        return True
    except ValueError:
        return False


def get_url_components(url: str) -> dict:
    """
    Parse a URL and return a dict with the following keys:
    scheme, netloc, host, port, path, query, fragment,
    domain, subdomain, tld
    """
    parsed = urlparse(url)
    extracted = tldextract.extract(url)

    domain = ""
    if extracted.domain and extracted.suffix:
        domain = f"{extracted.domain}.{extracted.suffix}"
    elif extracted.domain:
        domain = extracted.domain

    return {
        "scheme": parsed.scheme,
        "netloc": parsed.netloc,
        "host": parsed.hostname or "",
        "port": parsed.port,
        "path": parsed.path,
        "query": parsed.query,
        "fragment": parsed.fragment,
        "domain": domain,
        "subdomain": extracted.subdomain,
        "tld": extracted.suffix,
    }


def decode_url_encoding(url: str) -> str:
    """Percent-decode a URL string (e.g. %20 -> space)."""
    return unquote(url)


def count_redirects_in_chain(chain: list[str]) -> int:
    """
    Given a redirect chain (list of URLs visited), return the number of
    redirects, which is len(chain) - 1.

    An empty chain or single-element chain has 0 redirects.
    """
    if not chain:
        return 0
    return max(0, len(chain) - 1)
