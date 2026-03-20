"""
PhisMail — Header Authentication Analyzer
Validates SPF, DKIM, DMARC and detects infrastructure anomalies.
"""

import re
from typing import Dict, List, Optional, Any
from app.core.logging import get_logger

logger = get_logger(__name__)


# Known brands mapped to their legitimate sending domains
BRAND_DOMAIN_MAP: dict = {
    "microsoft":  ["microsoft.com", "outlook.com", "hotmail.com", "live.com", "msn.com"],
    "outlook":    ["microsoft.com", "outlook.com", "hotmail.com", "live.com"],
    "google":     ["google.com", "gmail.com", "googlemail.com"],
    "gmail":      ["google.com", "gmail.com", "googlemail.com"],
    "apple":      ["apple.com", "icloud.com"],
    "paypal":     ["paypal.com"],
    "amazon":     ["amazon.com", "amazonaws.com", "amazon.co.uk"],
    "facebook":   ["facebook.com", "fb.com", "meta.com"],
    "instagram":  ["instagram.com"],
    "twitter":    ["twitter.com", "t.co", "x.com"],
    "netflix":    ["netflix.com"],
    "dropbox":    ["dropbox.com"],
    "linkedin":   ["linkedin.com"],
    "yahoo":      ["yahoo.com", "yahoo.co.uk"],
    "chase":      ["chase.com", "jpmorgan.com"],
    "wellsfargo": ["wellsfargo.com"],
    "citibank":   ["citi.com", "citibank.com"],
    "dhl":        ["dhl.com"],
    "fedex":      ["fedex.com"],
    "ups":        ["ups.com"],
    "docusign":   ["docusign.com", "docusign.net"],
    "helpdesk":   [],   # generic term — always suspicious if from external domain
    "support":    [],
    "admin":      [],
    "noreply":    [],
    "security":   [],
    "alert":      [],
}

BULK_MAIL_HEADERS = [
    "list-unsubscribe",
    "list-unsubscribe-post",
    "feedback-id",
    "x-mailer",
    "x-mta-source",
    "x-delivery",
]

# Headers whose *values* are checked for ESP names
ESP_HEADERS = ["x-mailer", "x-mta-source", "feedback-id", "x-delivery", "x-originating-ip"]

# Known ESP name substrings (case-insensitive)
ESP_NAMES = [
    "netcorecloud", "sendgrid", "mailchimp", "amazonses", "amazon ses",
    "salesforce", "exacttarget", "marketo", "hubspot", "klaviyo",
    "mailjet", "mandrill", "postmark", "sparkpost", "constant contact",
    "campaignmonitor", "braze", "iterable",
]


class HeaderAnalysisResult:
    """Result of email header analysis."""

    def __init__(self):
        self.spf_pass: Optional[bool] = None
        self.dkim_pass: Optional[bool] = None
        self.dmarc_pass: Optional[bool] = None
        self.spf_fail: bool = False
        self.dkim_fail: bool = False
        self.dmarc_fail: bool = False
        self.reply_to_mismatch: bool = False
        self.return_path_mismatch: bool = False
        self.sender_domain_mismatch: bool = False
        self.bulk_mail_indicator: bool = False
        self.esp_detected: bool = False
        self.sender_domain: Optional[str] = None
        self.originating_ip: Optional[str] = None
        self.num_received_headers: int = 0
        self.smtp_hops: int = 0
        self.authentication_results: Dict[str, Any] = {}
        # Display name brand spoofing
        self.display_name_brand_spoofing: bool = False
        self.display_name_brand: Optional[str] = None
        self.display_name: Optional[str] = None


def analyze_headers(
    headers: Dict[str, str],
    sender: Optional[str],
    reply_to: Optional[str],
    return_path: Optional[str],
    originating_ip: Optional[str] = None,
    received_headers: Optional[List[str]] = None,
) -> HeaderAnalysisResult:
    """Analyze email headers for authentication and anomalies."""

    result = HeaderAnalysisResult()
    result.originating_ip = originating_ip

    # Count received headers (SMTP hops) — use the dedicated list when available
    if received_headers is not None:
        result.num_received_headers = len(received_headers)
    else:
        # Legacy fallback: dict-based (only captures last Received header)
        received_list = [v for k, v in headers.items() if k.lower() == "received"]
        if isinstance(received_list, str):
            received_list = [received_list]
        result.num_received_headers = len(received_list) if isinstance(received_list, list) else 0
    result.smtp_hops = result.num_received_headers

    # --- SPF: live DNS validation when IP and sender domain are available ---
    sender_domain = _extract_domain(sender)
    spf_live = validate_spf_live(originating_ip, sender_domain)

    if spf_live is not None:
        # Live validation succeeded — use real DNS result instead of trusting header
        result.spf_pass = spf_live
    else:
        # Fallback to header parsing when live validation is not possible
        # (e.g., no originating IP, no sender domain, DNS unreachable)
        auth_results = headers.get("Authentication-Results", "")
        result.spf_pass = _check_auth_result(auth_results, "spf")

    # --- DKIM/DMARC: still header-based (DKIM needs raw bytes, DMARC needs alignment) ---
    auth_results = headers.get("Authentication-Results", "")
    result.dkim_pass = _check_auth_result(auth_results, "dkim")
    result.dmarc_pass = _check_auth_result(auth_results, "dmarc")

    result.authentication_results = {
        "spf": "pass" if result.spf_pass else ("fail" if result.spf_pass is False else "unknown"),
        "spf_source": "live_dns" if spf_live is not None else "header",
        "dkim": "pass" if result.dkim_pass else ("fail" if result.dkim_pass is False else "unknown"),
        "dmarc": "pass" if result.dmarc_pass else ("fail" if result.dmarc_pass is False else "unknown"),
    }

    # Auth fail flags
    result.spf_fail = result.spf_pass is False
    result.dkim_fail = result.dkim_pass is False
    result.dmarc_fail = result.dmarc_pass is False

    # Bulk / marketing mail header detection
    headers_lower = {k.lower(): v for k, v in headers.items()}
    result.bulk_mail_indicator = any(h in headers_lower for h in BULK_MAIL_HEADERS)

    # ESP detection — scan known ESP headers for provider name substrings
    for esp_header in ESP_HEADERS:
        header_val = (headers_lower.get(esp_header) or "").lower()
        if any(esp_name in header_val for esp_name in ESP_NAMES):
            result.esp_detected = True
            break

    # Check reply-to mismatch
    reply_to_domain = _extract_domain(reply_to)
    return_path_domain = _extract_domain(return_path)

    result.sender_domain = sender_domain

    if sender_domain and reply_to_domain and sender_domain != reply_to_domain:
        result.reply_to_mismatch = True

    if sender_domain and return_path_domain and sender_domain != return_path_domain:
        result.return_path_mismatch = True

    # Check sender domain mismatch (From vs envelope)
    if sender_domain and return_path_domain and reply_to_domain:
        domains = {sender_domain, reply_to_domain, return_path_domain}
        if len(domains) > 1:
            result.sender_domain_mismatch = True

    # Display name brand spoofing detection
    if sender:
        display_name = _extract_display_name(sender)
        result.display_name = display_name
        if display_name:
            display_lower = display_name.lower()
            matched_brand = None
            for brand in BRAND_DOMAIN_MAP:
                if brand in display_lower:
                    matched_brand = brand
                    break
            if matched_brand is not None:
                result.display_name_brand = matched_brand
                legit_domains = BRAND_DOMAIN_MAP[matched_brand]
                sender_dom = sender_domain or ""
                # If brand has known domains, check if sender matches any
                if legit_domains:
                    is_legit = any(
                        sender_dom == d or sender_dom.endswith("." + d)
                        for d in legit_domains
                    )
                else:
                    # Generic brand word (helpdesk, admin, support) — always spoofing from external
                    is_legit = False
                if not is_legit:
                    result.display_name_brand_spoofing = True

    return result


def _check_auth_result(auth_header: str, mechanism: str) -> Optional[bool]:
    """Check SPF/DKIM/DMARC result from Authentication-Results header."""

    if not auth_header:
        return None

    auth_lower = auth_header.lower()

    # Look for pattern like "spf=pass" or "dkim=fail"
    pattern = rf"{mechanism}\s*=\s*(\w+)"
    match = re.search(pattern, auth_lower)

    if match:
        result = match.group(1)
        if result in ("pass", "bestguesspass"):
            return True
        elif result in ("fail", "softfail", "hardfail", "temperror", "permerror"):
            return False

    return None


def validate_spf_live(ip: Optional[str], sender_domain: Optional[str]) -> Optional[bool]:
    """
    Perform live SPF validation via DNS lookup using pyspf.

    Returns:
        True  — SPF pass (IP is authorized to send for this domain)
        False — SPF fail/softfail/permerror (IP is NOT authorized)
        None  — cannot validate (missing IP/domain, DNS error, or no SPF record)
    """
    if not ip or not sender_domain:
        return None

    try:
        import spf  # noqa: F811 — imported here for graceful degradation if pyspf not installed
        # spf.check returns (result, code, explanation)
        # result is one of: 'pass', 'fail', 'softfail', 'neutral', 'none',
        #                    'permerror', 'temperror'
        result, _code, _explanation = spf.check(i=ip, s=f"postmaster@{sender_domain}", h=sender_domain)

        logger.debug(
            "spf_live_validation",
            ip=ip,
            domain=sender_domain,
            result=result,
        )

        if result == "pass":
            return True
        elif result in ("fail", "softfail", "permerror"):
            return False
        else:
            # 'neutral', 'none', 'temperror' — inconclusive, fall back to header
            return None

    except Exception as exc:
        logger.warning("spf_live_validation_failed", ip=ip, domain=sender_domain, error=str(exc))
        return None


def _extract_display_name(address: Optional[str]) -> Optional[str]:
    """Extract display name from 'Display Name <email@domain.com>' format."""
    if not address:
        return None
    match = re.match(r'^"?([^"<]+?)"?\s*<', address.strip())
    if match:
        return match.group(1).strip()
    return None


def _extract_domain(address: Optional[str]) -> Optional[str]:
    """Extract domain from an email address."""

    if not address:
        return None

    # Handle "Name <email@domain.com>" format
    match = re.search(r"@([\w\.-]+)", address)
    if match:
        return match.group(1).lower()

    return None
