"""
PhisMail — URL Extractor
Extract URLs from email body text and HTML content using regex and
BeautifulSoup-based HTML parsing.
"""

import re
from typing import List, Optional
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from app.core.logging import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

URL_REGEX = re.compile(
    r'https?://[^\s<>"{}|\\^`\[\]\']+',
    re.IGNORECASE,
)

# Matches inline style attributes that hide elements
_HIDDEN_STYLE_RE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def extract_urls_from_text(text: str) -> List[str]:
    """Extract HTTP/HTTPS URLs from a plain-text string.

    Uses :data:`URL_REGEX` to find all candidate URLs, deduplicates
    them, and returns a sorted list.

    Args:
        text: Plain-text email body or any string that may contain URLs.

    Returns:
        A sorted, deduplicated list of URL strings.
    """

    if not text:
        return []

    found = set(URL_REGEX.findall(text))
    return sorted(found)


def extract_urls_from_html(html: str) -> List[str]:
    """Extract HTTP/HTTPS URLs from an HTML string.

    Parses the HTML with BeautifulSoup and collects:

    * ``href`` attributes from ``<a>`` tags.
    * ``src`` attributes from ``<img>``, ``<script>``, and ``<iframe>`` tags.

    Additionally runs :data:`URL_REGEX` against the visible text content
    of the parsed document.  Results are deduplicated and filtered to
    ``http``/``https`` schemes only.

    Args:
        html: Raw HTML string from the email body.

    Returns:
        A sorted, deduplicated list of URL strings.
    """

    if not html:
        return []

    urls: set = set()

    try:
        soup = BeautifulSoup(html, "html.parser")

        # Anchor hrefs
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if _is_http(href):
                urls.add(href)

        # Resource src attributes
        for tag in soup.find_all(["img", "script", "iframe"]):
            src = tag.get("src", "").strip()
            if _is_http(src):
                urls.add(src)

        # Regex scan over all text nodes
        text_content = soup.get_text(separator=" ")
        for match in URL_REGEX.finditer(text_content):
            candidate = match.group(0)
            if _is_http(candidate):
                urls.add(candidate)

    except Exception as exc:
        logger.warning("html_url_extraction_failed", error=str(exc))

    # Fallback: raw regex over the HTML source as well
    for match in URL_REGEX.finditer(html):
        candidate = match.group(0)
        if _is_http(candidate):
            urls.add(candidate)

    return sorted(urls)


def extract_all_urls(
    body_text: Optional[str],
    body_html: Optional[str],
) -> List[str]:
    """Combine URL extraction from plain text and HTML body parts.

    Merges results from :func:`extract_urls_from_text` and
    :func:`extract_urls_from_html`, deduplicates across both sources,
    and returns a sorted list capped at **50** URLs to avoid excessive
    downstream processing.

    Args:
        body_text: Plain-text email body, or ``None``.
        body_html: HTML email body, or ``None``.

    Returns:
        A sorted, deduplicated list of up to 50 URL strings.
    """

    combined: set = set()

    if body_text:
        combined.update(extract_urls_from_text(body_text))

    if body_html:
        combined.update(extract_urls_from_html(body_html))

    return sorted(combined)[:50]


def find_hidden_urls(html: str) -> List[str]:
    """Find URLs inside visually hidden HTML elements.

    Searches for elements whose ``style`` attribute contains
    ``display:none`` or ``visibility:hidden`` and extracts any URLs
    from their ``href``/``src`` attributes and inner text.  Hidden URLs
    are a common indicator of phishing and URL-redirect obfuscation.

    Args:
        html: Raw HTML string to inspect.

    Returns:
        A list of URL strings found inside hidden elements.
        May be empty; duplicate URLs within hidden elements are included
        as separate entries only once.
    """

    if not html:
        return []

    hidden_urls: set = set()

    try:
        soup = BeautifulSoup(html, "html.parser")

        for tag in soup.find_all(style=True):
            style_value = tag.get("style", "")
            if _HIDDEN_STYLE_RE.search(style_value):
                # Check href / src on the element itself
                for attr in ("href", "src"):
                    value = tag.get(attr, "").strip()
                    if _is_http(value):
                        hidden_urls.add(value)

                # Regex over the element's rendered text
                element_text = tag.get_text(separator=" ")
                for match in URL_REGEX.finditer(element_text):
                    hidden_urls.add(match.group(0))

                # Regex over the element's raw HTML
                raw = str(tag)
                for match in URL_REGEX.finditer(raw):
                    hidden_urls.add(match.group(0))

    except Exception as exc:
        logger.warning("hidden_url_detection_failed", error=str(exc))

    return list(hidden_urls)


def normalize_url_list(urls: List[str]) -> List[str]:
    """Strip whitespace, deduplicate preserving order, and filter short URLs.

    A URL must be longer than 10 characters after stripping to be
    retained.  The original order is preserved for the first occurrence
    of each URL.

    Args:
        urls: A list of raw URL strings, possibly containing duplicates
              or surrounding whitespace.

    Returns:
        An order-preserving, deduplicated list of URLs with length > 10.
    """

    seen: set = set()
    result: List[str] = []

    for url in urls:
        cleaned = url.strip()
        if len(cleaned) > 10 and cleaned not in seen:
            seen.add(cleaned)
            result.append(cleaned)

    return result


# ---------------------------------------------------------------------------
# Internal utilities
# ---------------------------------------------------------------------------


def _is_http(url: str) -> bool:
    """Return True if *url* has an http or https scheme."""
    lower = url.lower()
    return lower.startswith("http://") or lower.startswith("https://")
