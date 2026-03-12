"""
PhisMail — DNS Analysis Module
Dedicated DNS record querying extracted from whois_lookup.py, with
tenacity retry logic, per-record-type error handling, and optional
Redis caching.
"""

from dataclasses import dataclass, field
from typing import List, Optional

from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from app.core.logging import get_logger

logger = get_logger(__name__)

# Optional cache import — degrade gracefully when Redis is unavailable
try:
    from app.utils.cache import cache as _cache_service  # type: ignore
    HAS_CACHE = True
except Exception:  # pragma: no cover
    HAS_CACHE = False
    _cache_service = None  # type: ignore


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class DnsResult:
    """Structured result of DNS record queries for a single domain.

    Attributes:
        a_records: List of IPv4 address strings from A records.
        mx_records: Mail-exchanger hostnames from MX records.
        txt_records: Raw TXT record strings.
        ns_records: Authoritative nameserver hostnames from NS records.
        has_spf: ``True`` when at least one TXT record contains ``v=spf1``.
        has_dmarc: ``True`` when a DMARC policy record was found at
                   ``_dmarc.<domain>``.
        has_mx: ``True`` when at least one MX record is present.
        total_record_count: Sum of all records across all queried types.
    """

    a_records: List[str] = field(default_factory=list)
    mx_records: List[str] = field(default_factory=list)
    txt_records: List[str] = field(default_factory=list)
    ns_records: List[str] = field(default_factory=list)
    has_spf: bool = False
    has_dmarc: bool = False
    has_mx: bool = False
    total_record_count: int = 0


# ---------------------------------------------------------------------------
# Primary query function
# ---------------------------------------------------------------------------


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=8),
    retry=retry_if_exception_type(Exception),
    reraise=True,
)
def query_dns_records(domain: str, timeout: float = 3.0) -> DnsResult:
    """Query A, MX, TXT, and NS records for *domain* with retry logic.

    Each record type is queried independently so that a failure for one
    type (e.g. ``NXDOMAIN`` for MX) does not prevent the remaining
    types from being collected.  SPF presence is detected from TXT
    records; DMARC is probed by querying ``_dmarc.<domain>``.

    The tenacity decorator retries the entire function up to three times
    with exponential back-off on any exception, then re-raises.

    Args:
        domain: The domain name to query, e.g. ``"example.com"``.
        timeout: Per-query timeout in seconds passed to
                 :class:`dns.resolver.Resolver`.  Defaults to ``3.0``.

    Returns:
        A populated :class:`DnsResult` dataclass.
    """

    import dns.resolver
    import dns.exception

    result = DnsResult()
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    # --- A records ---
    try:
        answers = resolver.resolve(domain, "A")
        result.a_records = [str(r) for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        pass
    except Exception as exc:
        logger.warning("dns_a_query_failed", domain=domain, error=str(exc))

    # --- MX records ---
    try:
        answers = resolver.resolve(domain, "MX")
        result.mx_records = [str(r.exchange).rstrip(".") for r in answers]
        result.has_mx = len(result.mx_records) > 0
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        pass
    except Exception as exc:
        logger.warning("dns_mx_query_failed", domain=domain, error=str(exc))

    # --- TXT records (also checks SPF) ---
    try:
        answers = resolver.resolve(domain, "TXT")
        result.txt_records = [str(r) for r in answers]
        for txt in result.txt_records:
            if "v=spf1" in txt.lower():
                result.has_spf = True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        pass
    except Exception as exc:
        logger.warning("dns_txt_query_failed", domain=domain, error=str(exc))

    # --- NS records ---
    try:
        answers = resolver.resolve(domain, "NS")
        result.ns_records = [str(r).rstrip(".") for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        pass
    except Exception as exc:
        logger.warning("dns_ns_query_failed", domain=domain, error=str(exc))

    # --- DMARC (separate _dmarc subdomain query) ---
    dmarc_raw = check_dmarc_record(domain)
    if dmarc_raw:
        result.has_dmarc = True

    result.total_record_count = (
        len(result.a_records)
        + len(result.mx_records)
        + len(result.txt_records)
        + len(result.ns_records)
    )

    return result


# ---------------------------------------------------------------------------
# Focused helper functions
# ---------------------------------------------------------------------------


def check_dmarc_record(domain: str) -> Optional[str]:
    """Query ``_dmarc.<domain>`` for a DMARC TXT record.

    Args:
        domain: Base domain name, e.g. ``"example.com"``.

    Returns:
        The raw DMARC policy string (e.g. ``"v=DMARC1; p=reject; ..."``)
        if found, or ``None`` otherwise.
    """

    import dns.resolver
    import dns.exception

    dmarc_domain = f"_dmarc.{domain}"
    try:
        answers = dns.resolver.resolve(dmarc_domain, "TXT")
        for r in answers:
            record_str = str(r).strip('"')
            if "v=dmarc1" in record_str.lower():
                return record_str
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        pass
    except Exception as exc:
        logger.warning("dmarc_query_failed", domain=domain, error=str(exc))

    return None


def check_spf_record(domain: str) -> Optional[str]:
    """Find the SPF record for *domain* from its TXT records.

    Args:
        domain: Domain name to query, e.g. ``"example.com"``.

    Returns:
        The SPF TXT string (begins with ``v=spf1``) if present,
        or ``None`` if no SPF record exists or the query fails.
    """

    import dns.resolver
    import dns.exception

    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for r in answers:
            record_str = str(r).strip('"')
            if "v=spf1" in record_str.lower():
                return record_str
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        pass
    except Exception as exc:
        logger.warning("spf_query_failed", domain=domain, error=str(exc))

    return None


def get_ip_from_a_record(domain: str) -> Optional[str]:
    """Return the first A-record IPv4 address for *domain*.

    Args:
        domain: Domain name to resolve, e.g. ``"example.com"``.

    Returns:
        The first resolved IPv4 address string, or ``None`` if the
        query produces no results or fails.
    """

    import dns.resolver
    import dns.exception

    try:
        answers = dns.resolver.resolve(domain, "A")
        records = [str(r) for r in answers]
        return records[0] if records else None
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        pass
    except Exception as exc:
        logger.warning("a_record_query_failed", domain=domain, error=str(exc))

    return None
