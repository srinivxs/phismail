"""
PhisMail — URLHaus API Client
Checks a URL against the URLHaus abuse.ch malware-URL database via
their v1 REST API.
"""

from dataclasses import dataclass, field
from typing import List, Optional

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()

API_URL: str = "https://urlhaus-api.abuse.ch/v1/url/"
TIMEOUT: float = 5.0


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class URLHausResult:
    """Result of a URLHaus URL lookup.

    Attributes:
        matched: ``True`` when URLHaus returns ``query_status == "listed"``,
                 meaning the URL is actively tracked as malicious.
        threat: The threat category string reported by URLHaus (e.g.
                ``"malware_download"``), or ``None`` when not matched.
        tags: List of tags attached to the URLHaus entry (may be empty).
        date_added: ISO-8601 date string when the URL was first submitted,
                    or ``None`` when not available.
        error: Human-readable error description, or ``None`` on success.
    """

    matched: bool
    threat: Optional[str]
    tags: List[str] = field(default_factory=list)
    date_added: Optional[str] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def check_url(url: str) -> URLHausResult:
    """Check whether *url* is listed as malicious in the URLHaus database.

    Sends a POST request to the URLHaus v1 URL-lookup endpoint.  An
    optional ``Auth-Key`` header is included when
    ``settings.urlhaus_auth_key`` is configured, which may increase
    rate limits on the upstream service.

    Args:
        url: The URL to query, e.g.
             ``"http://malware-host.example.com/payload.exe"``.

    Returns:
        A :class:`URLHausResult` with ``matched=True`` and populated
        threat/tag metadata when the URL is listed.  On errors,
        ``matched=False`` and ``error`` describes the failure.
    """

    headers: dict = {}
    if settings.urlhaus_auth_key:
        headers["Auth-Key"] = settings.urlhaus_auth_key

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            response = await client.post(
                API_URL,
                data={"url": url},
                headers=headers,
            )
            response.raise_for_status()
            data = response.json()

        query_status: str = data.get("query_status", "")
        matched = query_status == "listed"

        return URLHausResult(
            matched=matched,
            threat=data.get("threat") or None,
            tags=data.get("tags") or [],
            date_added=data.get("date_added") or None,
        )

    except httpx.TimeoutException as exc:
        logger.warning("urlhaus_timeout", url=url, error=str(exc))
        return URLHausResult(
            matched=False,
            threat=None,
            error=f"timeout: {exc}",
        )
    except httpx.HTTPStatusError as exc:
        logger.warning(
            "urlhaus_http_error",
            url=url,
            status_code=exc.response.status_code,
            error=str(exc),
        )
        return URLHausResult(
            matched=False,
            threat=None,
            error=f"http_error_{exc.response.status_code}",
        )
    except Exception as exc:
        logger.warning("urlhaus_check_failed", url=url, error=str(exc))
        return URLHausResult(
            matched=False,
            threat=None,
            error=str(exc),
        )
