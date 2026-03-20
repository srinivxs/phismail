"""
PhisMail — AbuseIPDB IP Reputation Client
Queries the AbuseIPDB API for IP abuse confidence scores.
"""

from typing import Optional
import httpx

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)

TIMEOUT = 5.0

# ISO country codes considered high-risk for phishing infrastructure
HIGH_RISK_COUNTRIES = {
    "RU", "CN", "NG", "BR", "IN", "VN", "PK", "ID", "UA", "RO",
    "BD", "PH", "KE", "GH", "TH", "EG", "ZA", "MA", "KR", "IR",
}


class IpReputationResult:
    """Result of AbuseIPDB IP reputation lookup."""

    def __init__(self):
        self.ip: Optional[str] = None
        self.abuse_confidence_score: int = 0
        self.country_code: Optional[str] = None
        self.isp: Optional[str] = None
        self.is_tor: bool = False
        self.total_reports: int = 0
        self.ip_blacklisted: bool = False
        self.country_risk_score: float = 0.0


async def check_ip_reputation(ip: Optional[str]) -> Optional[IpReputationResult]:
    """
    Query AbuseIPDB for IP reputation data.

    Returns None if no IP provided or API key not configured.
    Degrades gracefully on errors.
    """
    if not ip:
        return None

    settings = get_settings()
    if not settings.abuseipdb_api_key:
        logger.debug("abuseipdb_skipped", reason="API key not configured")
        return None

    result = IpReputationResult()
    result.ip = ip

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            response = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={
                    "Key": settings.abuseipdb_api_key,
                    "Accept": "application/json",
                },
            )

            if response.status_code != 200:
                logger.warning(
                    "abuseipdb_http_error",
                    ip=ip,
                    status=response.status_code,
                )
                return None

            data = response.json().get("data", {})

            result.abuse_confidence_score = data.get("abuseConfidenceScore", 0)
            result.country_code = data.get("countryCode")
            result.isp = data.get("isp")
            result.is_tor = data.get("isTor", False)
            result.total_reports = data.get("totalReports", 0)

            # Flag as blacklisted if abuse confidence > 50%
            result.ip_blacklisted = result.abuse_confidence_score > 50

            # Country risk score: 1.0 for high-risk countries, 0.0 otherwise
            result.country_risk_score = (
                1.0 if result.country_code in HIGH_RISK_COUNTRIES else 0.0
            )

            logger.info(
                "abuseipdb_lookup",
                ip=ip,
                confidence=result.abuse_confidence_score,
                country=result.country_code,
                blacklisted=result.ip_blacklisted,
            )

            return result

    except Exception as exc:
        logger.warning("abuseipdb_lookup_failed", ip=ip, error=str(exc))
        return None
