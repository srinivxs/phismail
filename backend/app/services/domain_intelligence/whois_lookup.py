"""
PhisMail — Domain Intelligence Services
WHOIS lookups and DNS analysis with Redis caching and tenacity retries.
"""

import json
from datetime import datetime
from typing import Optional, Dict, Any, List

from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from app.core.logging import get_logger

logger = get_logger(__name__)


class WhoisResult:
    """Result of a WHOIS lookup."""

    def __init__(self):
        self.domain: str = ""
        self.registrar: Optional[str] = None
        self.registration_date: Optional[datetime] = None
        self.expiry_date: Optional[datetime] = None
        self.domain_age_days: Optional[int] = None
        self.nameservers: List[str] = []
        self.error: Optional[str] = None


class DnsResult:
    """Result of DNS record queries."""

    def __init__(self):
        self.domain: str = ""
        self.a_records: List[str] = []
        self.mx_records: List[str] = []
        self.txt_records: List[str] = []
        self.ns_records: List[str] = []
        self.has_mx_record: bool = False
        self.has_spf_record: bool = False
        self.has_dmarc_record: bool = False
        self.dns_record_count: int = 0
        self.error: Optional[str] = None


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=8),
    retry=retry_if_exception_type(Exception),
    reraise=True,
)
def whois_lookup(domain: str) -> WhoisResult:
    """Perform WHOIS lookup with retry logic."""

    result = WhoisResult()
    result.domain = domain

    try:
        import whois
        w = whois.whois(domain)

        result.registrar = w.registrar

        # Handle registration date
        if w.creation_date:
            if isinstance(w.creation_date, list):
                result.registration_date = w.creation_date[0]
            else:
                result.registration_date = w.creation_date

        # Handle expiry date
        if w.expiration_date:
            if isinstance(w.expiration_date, list):
                result.expiry_date = w.expiration_date[0]
            else:
                result.expiry_date = w.expiration_date

        # Calculate domain age
        if result.registration_date:
            delta = datetime.utcnow() - result.registration_date
            result.domain_age_days = delta.days

        # Nameservers
        if w.name_servers:
            if isinstance(w.name_servers, list):
                result.nameservers = [ns.lower() for ns in w.name_servers if ns]
            else:
                result.nameservers = [w.name_servers.lower()]

    except Exception as e:
        result.error = str(e)
        logger.warning("whois_lookup_failed", domain=domain, error=str(e))

    return result


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=8),
    retry=retry_if_exception_type(Exception),
    reraise=True,
)
def dns_lookup(domain: str) -> DnsResult:
    """Perform DNS record queries with retry logic."""

    import dns.resolver

    result = DnsResult()
    result.domain = domain
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    # A records
    try:
        answers = resolver.resolve(domain, "A")
        result.a_records = [str(r) for r in answers]
    except Exception:
        pass

    # MX records
    try:
        answers = resolver.resolve(domain, "MX")
        result.mx_records = [str(r.exchange).rstrip(".") for r in answers]
        result.has_mx_record = len(result.mx_records) > 0
    except Exception:
        pass

    # TXT records (check for SPF)
    try:
        answers = resolver.resolve(domain, "TXT")
        result.txt_records = [str(r) for r in answers]
        for txt in result.txt_records:
            if "v=spf1" in txt.lower():
                result.has_spf_record = True
    except Exception:
        pass

    # NS records
    try:
        answers = resolver.resolve(domain, "NS")
        result.ns_records = [str(r).rstrip(".") for r in answers]
    except Exception:
        pass

    # Check for DMARC
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = resolver.resolve(dmarc_domain, "TXT")
        for r in answers:
            if "v=dmarc1" in str(r).lower():
                result.has_dmarc_record = True
    except Exception:
        pass

    result.dns_record_count = (
        len(result.a_records) + len(result.mx_records)
        + len(result.txt_records) + len(result.ns_records)
    )

    return result
