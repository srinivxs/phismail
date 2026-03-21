"""
PhisMail — OpenPhish Feed Client
Downloads and queries the OpenPhish community phishing-URL feed.
The feed is cached in Redis (TTL = 3600 s) to avoid hammering the
upstream endpoint on every check.
"""

from dataclasses import dataclass, field
from typing import List, Optional

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()

# Feed endpoint and request timeout
FEED_URL: str = settings.openphish_feed_url
TIMEOUT: float = 5.0

# Cache key used to store the raw feed in Redis
_FEED_CACHE_KEY = "openphish:feed"
_FEED_CACHE_TTL = 3600  # seconds

# Optional cache import — degrade gracefully when Redis is unavailable
try:
    from app.core.cache import cache as _cache_service  # type: ignore
    HAS_CACHE = True
except Exception:  # pragma: no cover
    HAS_CACHE = False
    _cache_service = None  # type: ignore


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class OpenPhishResult:
    """Result of an OpenPhish feed lookup.

    Attributes:
        matched: ``True`` when *url* was found in the feed.
        feed_url: The feed endpoint that was queried.
        error: Human-readable error description, or ``None`` on success.
    """

    matched: bool
    feed_url: str
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def check_url(url: str) -> OpenPhishResult:
    """Check whether *url* appears in the OpenPhish community feed.

    The feed is downloaded once per cache TTL (3600 s) and stored in
    Redis under the key ``"openphish:feed"``.  When the cache is
    unavailable the feed is fetched on every call.  The match is a
    case-insensitive exact comparison against each line of the feed.

    Args:
        url: The URL to look up, e.g.
             ``"http://evil.example.com/login"``.

    Returns:
        An :class:`OpenPhishResult` with ``matched=True`` if the URL
        was found in the feed.  On network or parse errors,
        ``matched=False`` and ``error`` is set to a description.
    """

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            feed_lines = await _get_cached_feed(client)

        url_lower = url.lower()
        matched = any(url_lower == line.lower() for line in feed_lines)

        return OpenPhishResult(matched=matched, feed_url=FEED_URL)

    except httpx.TimeoutException as exc:
        logger.warning("openphish_timeout", feed_url=FEED_URL, error=str(exc))
        return OpenPhishResult(
            matched=False,
            feed_url=FEED_URL,
            error=f"timeout: {exc}",
        )
    except Exception as exc:
        logger.warning("openphish_check_failed", feed_url=FEED_URL, error=str(exc))
        return OpenPhishResult(
            matched=False,
            feed_url=FEED_URL,
            error=str(exc),
        )


async def fetch_feed(client: httpx.AsyncClient) -> List[str]:
    """Download the OpenPhish feed and return individual URL lines.

    Args:
        client: An active :class:`httpx.AsyncClient` instance to use
                for the HTTP GET request.

    Returns:
        A list of stripped, non-empty URL strings from the feed.

    Raises:
        :class:`httpx.HTTPStatusError`: when the server returns a
            non-2xx status code.
        :class:`httpx.RequestError`: on network-level failures.
    """

    response = await client.get(FEED_URL)
    response.raise_for_status()
    return [line.strip() for line in response.text.splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _get_cached_feed(client: httpx.AsyncClient) -> List[str]:
    """Return feed lines from Redis cache or download fresh if needed.

    Args:
        client: An active :class:`httpx.AsyncClient` used when a cache
                miss requires downloading the feed.

    Returns:
        List of stripped, non-empty URL strings.
    """

    if HAS_CACHE and _cache_service is not None:
        cached = _cache_service.get(_FEED_CACHE_KEY)
        if cached is not None:
            # Cached as a JSON list of strings
            if isinstance(cached, list):
                return cached

    # Cache miss or no cache — fetch from upstream
    lines = await fetch_feed(client)

    if HAS_CACHE and _cache_service is not None:
        _cache_service.set(_FEED_CACHE_KEY, lines, _FEED_CACHE_TTL)

    return lines
