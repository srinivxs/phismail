"""
PhisMail — PhishTank API Client
Checks a URL against the PhishTank verified-phish database via their
JSON REST API.
"""

from dataclasses import dataclass
from typing import Optional

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()

API_URL: str = "https://checkurl.phishtank.com/checkurl/"
TIMEOUT: float = 5.0


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class PhishTankResult:
    """Result of a PhishTank URL lookup.

    Attributes:
        matched: ``True`` when PhishTank reports the URL is a known
                 phish that is both in the database and currently valid.
        phish_id: The PhishTank internal phish identifier, or ``None``
                  when not matched or the API returned no ID.
        verified: ``True`` when the phish entry has been verified by
                  PhishTank community members.
        error: Human-readable error string, or ``None`` on success.
    """

    matched: bool
    phish_id: Optional[str]
    verified: bool
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def check_url(url: str) -> PhishTankResult:
    """Check whether *url* is listed as a verified phish on PhishTank.

    Sends a POST request to the PhishTank Check URL endpoint using the
    application-configured API key.  When no API key is configured, the
    function returns immediately with a result indicating the check was
    skipped.

    Args:
        url: The URL to verify, e.g.
             ``"http://suspicious.example.com/login"``.

    Returns:
        A :class:`PhishTankResult` with ``matched=True`` if the URL is
        both in the PhishTank database and currently considered a valid
        phish.  On API errors or missing API key, ``matched=False`` and
        ``error`` describes the reason.
    """

    if not settings.phishtank_api_key:
        return PhishTankResult(
            matched=False,
            phish_id=None,
            verified=False,
            error="no_api_key",
        )

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            response = await client.post(
                API_URL,
                data={
                    "url": url,
                    "format": "json",
                    "app_key": settings.phishtank_api_key,
                },
                headers={"User-Agent": "PhisMail/1.0"},
            )
            response.raise_for_status()
            data = response.json()

        api_results = data.get("results", {})
        in_database: bool = bool(api_results.get("in_database", False))
        valid: bool = bool(api_results.get("valid", False))
        matched = in_database and valid

        phish_id: Optional[str] = api_results.get("phish_id")
        if phish_id is not None:
            phish_id = str(phish_id)

        verified: bool = bool(api_results.get("verified", False))

        return PhishTankResult(
            matched=matched,
            phish_id=phish_id,
            verified=verified,
        )

    except httpx.TimeoutException as exc:
        logger.warning("phishtank_timeout", url=url, error=str(exc))
        return PhishTankResult(
            matched=False,
            phish_id=None,
            verified=False,
            error=f"timeout: {exc}",
        )
    except httpx.HTTPStatusError as exc:
        logger.warning(
            "phishtank_http_error",
            url=url,
            status_code=exc.response.status_code,
            error=str(exc),
        )
        return PhishTankResult(
            matched=False,
            phish_id=None,
            verified=False,
            error=f"http_error_{exc.response.status_code}",
        )
    except Exception as exc:
        logger.warning("phishtank_check_failed", url=url, error=str(exc))
        return PhishTankResult(
            matched=False,
            phish_id=None,
            verified=False,
            error=str(exc),
        )
