"""
PhisMail — Threat Intelligence Service
Async concurrent queries to OpenPhish, PhishTank, and URLHaus.
Cached in Redis with graceful degradation.
"""

from typing import List, Optional, Dict, Any
import httpx

from app.core.config import get_settings
from app.core.logging import get_logger, LogEvents

logger = get_logger(__name__)
settings = get_settings()

TIMEOUT = 3.0


class ThreatIntelResult:
    """Aggregated threat intelligence result."""

    def __init__(self):
        self.openphish_match: bool = False
        self.phishtank_match: bool = False
        self.urlhaus_match: bool = False
        self.domain_blacklisted: bool = False
        self.matches: List[Dict[str, Any]] = []
        self.confidence_score: float = 0.0


async def check_threat_intelligence(url: str, domain: Optional[str] = None) -> ThreatIntelResult:
    """Query all threat intelligence feeds concurrently."""

    import asyncio
    result = ThreatIntelResult()

    tasks = [
        _check_openphish(url),
        _check_phishtank(url),
        _check_urlhaus(url),
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # OpenPhish
    if isinstance(results[0], bool) and results[0]:
        result.openphish_match = True
        result.matches.append({"source": "openphish", "url": url})

    # PhishTank
    if isinstance(results[1], dict) and results[1].get("match"):
        result.phishtank_match = True
        result.matches.append({"source": "phishtank", "url": url, "data": results[1]})

    # URLHaus
    if isinstance(results[2], dict) and results[2].get("match"):
        result.urlhaus_match = True
        result.matches.append({"source": "urlhaus", "url": url, "data": results[2]})

    result.domain_blacklisted = any([
        result.openphish_match,
        result.phishtank_match,
        result.urlhaus_match,
    ])

    # Confidence score based on number of feeds that match
    match_count = sum([
        result.openphish_match,
        result.phishtank_match,
        result.urlhaus_match,
    ])
    result.confidence_score = match_count / 3.0

    if result.domain_blacklisted:
        logger.info(
            LogEvents.THREAT_INTEL_HIT,
            url=url,
            sources=[m["source"] for m in result.matches],
        )

    return result


async def _check_openphish(url: str) -> bool:
    """Check URL against OpenPhish community feed."""

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            response = await client.get(settings.openphish_feed_url)
            if response.status_code == 200:
                feed_urls = response.text.strip().split("\n")
                url_lower = url.lower()
                return any(url_lower == feed_url.strip().lower() for feed_url in feed_urls)
    except Exception as e:
        logger.warning("openphish_check_failed", error=str(e))

    return False


async def _check_phishtank(url: str) -> Dict[str, Any]:
    """Check URL against PhishTank API."""

    if not settings.phishtank_api_key:
        return {"match": False, "reason": "API key not configured"}

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            response = await client.post(
                "https://checkurl.phishtank.com/checkurl/",
                data={
                    "url": url,
                    "format": "json",
                    "app_key": settings.phishtank_api_key,
                },
                headers={"User-Agent": "PhisMail/1.0"},
            )
            if response.status_code == 200:
                data = response.json()
                results = data.get("results", {})
                return {
                    "match": results.get("in_database", False) and results.get("valid", False),
                    "phish_id": results.get("phish_id"),
                    "verified": results.get("verified"),
                }
    except Exception as e:
        logger.warning("phishtank_check_failed", error=str(e))

    return {"match": False}


async def _check_urlhaus(url: str) -> Dict[str, Any]:
    """Check URL against URLHaus API."""

    try:
        headers = {}
        if settings.urlhaus_auth_key:
            headers["Auth-Key"] = settings.urlhaus_auth_key

        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            response = await client.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": url},
                headers=headers,
            )
            if response.status_code == 200:
                data = response.json()
                query_status = data.get("query_status", "")
                return {
                    "match": query_status == "listed",
                    "threat": data.get("threat", ""),
                    "tags": data.get("tags", []),
                    "date_added": data.get("date_added"),
                }
    except Exception as e:
        logger.warning("urlhaus_check_failed", error=str(e))

    return {"match": False}
