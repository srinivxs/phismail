"""
PhisMail — Risk Scoring Rule Engine
Dual-bucket scoring: suspicion_score − trust_score with SHAP-compatible explainability.
Reduces false positives on legitimate marketing/bulk email while preserving detection
of genuine phishing campaigns.
"""

from typing import Dict, List, Tuple, Optional
from app.core.logging import get_logger

logger = get_logger(__name__)

# =============================================================================
# Suspicion Weights  (positive values → increase risk)
# =============================================================================

SUSPICION_WEIGHTS: Dict[str, float] = {
    # --- Authentication failures ---
    "spf_fail": 20.0,
    "dkim_fail": 25.0,
    "dmarc_fail": 30.0,

    # --- Header mismatches ---
    "reply_to_mismatch": 15.0,
    "return_path_mismatch": 5.0,
    "sender_domain_mismatch": 10.0,

    # --- URL structural ---
    "url_length": 0.04,           # per character above baseline
    "num_subdomains": 3.0,
    "contains_ip_address": 30.0,  # §8: ip_address_url +30
    "url_shortened": 8.0,
    "url_entropy_score": 3.0,
    "username_in_url": 15.0,

    # --- URL obfuscation ---
    "percent_encoding_count": 2.0,
    "double_slash_redirect": 10.0,
    "mixed_case_domain": 5.0,

    # --- Domain age (tiered, §8) ---
    "domain_very_recent": 40.0,        # < 7 days  → +40
    "domain_recent_registration": 25.0, # 7–30 days → +25

    # --- Threat intelligence (§8) ---
    "openphish_match": 50.0,
    "phishtank_match": 50.0,
    "urlhaus_match": 50.0,
    "domain_blacklisted": 50.0,
    "ip_blacklisted": 40.0,
    "country_risk_score": 10.0,

    # --- Brand impersonation (contextual, §4) ---
    "brand_sender_domain_mismatch": 30.0,
    "brand_homograph_detected": 30.0,   # §8: punycode_domain +30

    # --- Redirect behaviour ---
    "redirect_count": 3.0,
    "final_domain_mismatch": 15.0,
    "redirect_to_ip": 12.0,
    "meta_refresh_detected": 8.0,

    # --- NLP / content (reduced §5) ---
    "urgency_keyword_count": 5.0,
    "credential_request_keywords": 10.0,
    "financial_request_keywords": 5.0,
    "security_alert_keywords": 5.0,
    "threat_language_score": 10.0,
    "imperative_language_score": 5.0,

    # --- URL domain unrelated to sender (§6) ---
    "url_domain_unrelated_to_sender": 15.0,

    # --- Attachment risk (§8) ---
    "has_executable_attachment": 40.0,
    "has_script_attachment": 35.0,
    "has_macro_document": 35.0,
    "double_extension_detected": 40.0,
    "mime_mismatch_detected": 15.0,
    "archive_with_executable": 30.0,

    # --- Email structure ---
    "javascript_in_email": 15.0,
    "hidden_links_detected": 12.0,
    "num_forms": 8.0,

    # --- Display name / sender spoofing (§1, §5) ---
    "display_name_brand_spoofing": 35.0,   # header signal — NOT content-only

    # --- Webmail & helpdesk impersonation (§2, §4) ---
    "webmail_phishing_phrase_count": 15.0, # per occurrence
    "helpdesk_impersonation_detected": 25.0,
    "generic_anchor_link_detected": 20.0,
}

# =============================================================================
# Trust Weights  (positive values → reduce risk when feature is present)
# =============================================================================

TRUST_WEIGHTS: Dict[str, float] = {
    # --- Authentication passes (§2) ---
    "spf_pass": 10.0,
    "dkim_pass": 15.0,
    "dmarc_pass": 20.0,
    "authentication_all_pass": 15.0,   # bonus when all three pass

    # --- Bulk / marketing mail (§3) ---
    "bulk_mail_indicator": 15.0,
    "esp_detected": 10.0,

    # --- Brand legitimacy (§4) ---
    "brand_sender_domain_match": 10.0,

    # --- URL domain consistent with sender (§6) ---
    "url_domain_matches_sender": 10.0,
    "url_domain_subdomain_of_sender": 10.0,
    "url_domain_cdn": 5.0,

    # --- Marketing template signals (§7) ---
    "has_unsubscribe_link": 5.0,
    "has_tracking_pixel": 5.0,
    "marketing_template_signals": 5.0,

    # --- Domain age trust (older = safer) ---
    "domain_age_days": 0.01,           # capped in scorer
}

# =============================================================================
# Pure content-only features (§5 — cannot alone produce PHISHING verdict)
# =============================================================================

CONTENT_ONLY_FEATURES = {
    "urgency_keyword_count",
    "credential_request_keywords",
    "financial_request_keywords",
    "security_alert_keywords",
    "threat_language_score",
    "imperative_language_score",
    # Webmail/helpdesk NLP signals — body content only, require a non-content signal for PHISHING
    "webmail_phishing_phrase_count",
    "helpdesk_impersonation_detected",
    "generic_anchor_link_detected",
}

# =============================================================================
# Indicator Severity Mapping
# =============================================================================

SEVERITY_MAP: Dict[str, str] = {
    # CRITICAL
    "openphish_match": "CRITICAL",
    "phishtank_match": "CRITICAL",
    "urlhaus_match": "CRITICAL",
    "domain_blacklisted": "CRITICAL",
    "ip_blacklisted": "HIGH",

    # HIGH
    "domain_very_recent": "HIGH",
    "domain_recent_registration": "HIGH",
    "reply_to_mismatch": "HIGH",
    "return_path_mismatch": "LOW",
    "brand_homograph_detected": "HIGH",
    "brand_sender_domain_mismatch": "HIGH",
    "has_executable_attachment": "HIGH",
    "double_extension_detected": "HIGH",
    "contains_ip_address": "HIGH",
    "dmarc_fail": "HIGH",

    # MEDIUM
    "spf_fail": "MEDIUM",
    "dkim_fail": "MEDIUM",
    "url_shortened": "MEDIUM",
    "username_in_url": "MEDIUM",
    "credential_request_keywords": "MEDIUM",
    "financial_request_keywords": "MEDIUM",
    "has_macro_document": "MEDIUM",
    "javascript_in_email": "MEDIUM",
    "final_domain_mismatch": "MEDIUM",
    "hidden_links_detected": "MEDIUM",
    "url_domain_unrelated_to_sender": "MEDIUM",

    # LOW
    "urgency_keyword_count": "LOW",
    "brand_keyword_present": "LOW",
    "mixed_case_domain": "LOW",
    "percent_encoding_count": "LOW",
    "sender_domain_mismatch": "LOW",
    "country_risk_score": "LOW",

    # HIGH — new phishing detection signals
    "display_name_brand_spoofing": "HIGH",
    "webmail_phishing_phrase_count": "HIGH",
    "helpdesk_impersonation_detected": "HIGH",
    "generic_anchor_link_detected": "HIGH",
}


class RiskScoringResult:
    """Result of dual-bucket risk scoring."""

    def __init__(self):
        self.risk_score: float = 0.0
        self.suspicion_score: float = 0.0
        self.trust_score: float = 0.0
        self.verdict: str = "SAFE"
        self.indicators: List[Dict] = []
        self.top_contributors: List[Dict] = []


def _build_detail(feature_name: str, feature_value: float, context: Dict) -> str:
    """Generate a human-readable detail string for each indicator type."""

    sender = context.get("sender", "")
    reply_to = context.get("reply_to", "")
    return_path = context.get("return_path", "")
    primary_domain = context.get("primary_domain", "")
    domain_age_days = context.get("domain_age_days")
    registrar = context.get("registrar", "")
    registration_date = context.get("registration_date", "")
    brand_keyword = context.get("brand_keyword", "")
    nlp_patterns = context.get("nlp_patterns", [])
    urls = context.get("urls", [])
    attachments = context.get("attachments", [])

    if feature_name == "reply_to_mismatch":
        return (
            f"From: {sender} → Reply-To: {reply_to} — "
            "Replies go to a different domain than the sender. "
            "This is a common phishing tactic to intercept responses."
        )
    if feature_name == "return_path_mismatch":
        return (
            f"From: {sender} → Return-Path: {return_path} — "
            "Bounce emails are routed to a different domain. "
            "Legitimate senders keep these consistent."
        )
    if feature_name == "sender_domain_mismatch":
        domains = {d for d in [sender, reply_to, return_path] if d}
        return (
            f"Conflicting domains across headers: {', '.join(domains)} — "
            "From, Reply-To, and Return-Path should all share the same domain."
        )
    if feature_name == "spf_fail":
        return (
            "SPF authentication FAILED — the sending server is not authorised to send "
            f"email on behalf of {primary_domain or 'this domain'}. "
            "This is a strong indicator of email spoofing."
        )
    if feature_name == "dkim_fail":
        return (
            "DKIM signature verification FAILED — the email's cryptographic signature "
            "is invalid or missing, meaning it may have been tampered with in transit."
        )
    if feature_name == "dmarc_fail":
        return (
            f"DMARC policy check FAILED for {primary_domain or 'sender domain'} — "
            "the domain owner's policy was not satisfied. This strongly suggests spoofing."
        )
    if feature_name == "financial_request_keywords":
        matched = [p.split(":", 1)[1] for p in nlp_patterns if p.startswith("financial:")][:5]
        kw = ", ".join(f'"{k}"' for k in matched) if matched else f"{int(feature_value)} occurrences"
        return (
            f"Detected {int(feature_value)} financial keyword(s): {kw}. "
            "These are used to create pressure around money or payments."
        )
    if feature_name == "credential_request_keywords":
        matched = [p.split(":", 1)[1] for p in nlp_patterns if p.startswith("credential:")][:5]
        kw = ", ".join(f'"{k}"' for k in matched) if matched else f"{int(feature_value)} occurrences"
        return (
            f"Detected {int(feature_value)} credential-harvesting keyword(s): {kw}. "
            "These phrases are designed to trick users into submitting login or personal information."
        )
    if feature_name == "urgency_keyword_count":
        matched = [p.split(":", 1)[1] for p in nlp_patterns if p.startswith("urgency:")][:5]
        kw = ", ".join(f'"{k}"' for k in matched) if matched else f"{int(feature_value)} occurrences"
        return (
            f"Detected {int(feature_value)} urgency keyword(s): {kw}. "
            "Urgency language pressures recipients into acting without thinking."
        )
    if feature_name == "threat_language_score":
        total = len([p for p in nlp_patterns if any(p.startswith(t) for t in ("urgency:", "credential:", "financial:", "security:"))])
        return (
            f"High threat language score ({feature_value:.2f}) based on {total} social engineering "
            "signals across urgency, credential, financial, and security alert patterns."
        )
    if feature_name == "imperative_language_score":
        return (
            f"Imperative language score: {feature_value:.2f} — "
            "Email uses commanding phrases like 'click here', 'download this', or 'verify now'."
        )
    if feature_name == "hidden_links_detected":
        return (
            "Email contains hyperlinks where the visible text does not match the actual URL destination. "
            "This is a classic technique to disguise malicious links as legitimate ones."
        )
    if feature_name == "url_length":
        url_sample = urls[0] if urls else ""
        return (
            f"URL length: {int(feature_value)} characters — "
            "Excessively long URLs are used to hide the true destination or evade filters."
            + (f" Example: {url_sample[:80]}..." if len(url_sample) > 80 else (f" URL: {url_sample}" if url_sample else ""))
        )
    if feature_name == "num_subdomains":
        return (
            f"{int(feature_value)} subdomain(s) detected — attackers stack subdomains "
            "(e.g. secure.login.paypal.evil.com) to make URLs appear legitimate."
        )
    if feature_name == "url_entropy_score":
        url_sample = urls[0] if urls else ""
        return (
            f"URL entropy: {feature_value:.4f} (high) — high randomness suggests machine-generated or obfuscated addresses."
            + (f" URL: {url_sample[:80]}" if url_sample else "")
        )
    if feature_name == "percent_encoding_count":
        return (
            f"{int(feature_value)} percent-encoded character(s) in URL — "
            "encoding like %2F or %40 is used to disguise special characters and bypass scanners."
        )
    if feature_name == "contains_ip_address":
        url_sample = urls[0] if urls else ""
        return (
            "URL uses a raw IP address instead of a domain name — "
            "legitimate services do not send links to bare IP addresses."
            + (f" URL: {url_sample}" if url_sample else "")
        )
    if feature_name == "url_shortened":
        return (
            "URL uses a known shortening service — "
            "shortened URLs hide the true destination and are commonly abused in phishing."
        )
    if feature_name == "username_in_url":
        return (
            "URL contains a credentials segment (e.g. https://paypal.com@evil.com) — "
            "the real destination is after '@', not before it."
        )
    if feature_name == "url_domain_unrelated_to_sender":
        return (
            f"The URL domain is unrelated to the sender domain ({sender}) — "
            "legitimate mailers send links on their own infrastructure or known ESP domains."
        )
    if feature_name == "final_domain_mismatch":
        return (
            "After following all redirects the final destination domain differs from the original link — "
            "a multi-hop redirect chain designed to conceal the true phishing page."
        )
    if feature_name in ("domain_very_recent", "domain_recent_registration"):
        age_str = f"{int(domain_age_days)} days old" if domain_age_days is not None else "recently registered"
        reg_str = f" (registered {registration_date})" if registration_date else ""
        reg_str2 = f" via {registrar}" if registrar else ""
        threshold = "7" if feature_name == "domain_very_recent" else "30"
        return (
            f"Domain '{primary_domain}' is {age_str}{reg_str}{reg_str2} — "
            f"domains younger than {threshold} days are a strong phishing indicator. "
            "Attackers register fresh domains to avoid blocklists."
        )
    if feature_name == "brand_sender_domain_mismatch":
        return (
            f"Brand keyword '{brand_keyword or 'known brand'}' detected but the sender domain "
            f"({sender}) does not match the brand's legitimate domain — "
            "this is a strong impersonation signal."
        )
    if feature_name == "brand_homograph_detected":
        return (
            f"Homograph attack detected on domain '{primary_domain}' — "
            "Unicode characters visually identical to ASCII are used to create fake lookalike domains."
        )
    if feature_name == "has_executable_attachment":
        exe_files = [a.get("filename", "unknown") for a in attachments if a.get("is_executable")]
        names = ", ".join(exe_files) if exe_files else "attachment"
        return f"Executable attachment detected: {names} — a primary malware delivery vector."
    if feature_name == "double_extension_detected":
        files = [a.get("filename", "unknown") for a in attachments if a.get("double_extension")]
        names = ", ".join(files) if files else "attachment"
        return f"Double-extension file detected: {names} — disguises executables as harmless documents."
    if feature_name == "has_macro_document":
        files = [a.get("filename", "unknown") for a in attachments if a.get("has_macros")]
        names = ", ".join(files) if files else "attachment"
        return f"Office document with macros detected: {names} — commonly used to execute malicious code."
    if feature_name == "javascript_in_email":
        return "JavaScript detected in email body — legitimate emails do not contain JavaScript."
    if feature_name == "openphish_match":
        return "URL matched in OpenPhish feed — this URL is an actively reported phishing site."
    if feature_name == "phishtank_match":
        return "URL matched in PhishTank database — confirmed phishing site."
    if feature_name == "urlhaus_match":
        return "URL matched in URLhaus malware feed — associated with malware distribution."
    if feature_name == "domain_blacklisted":
        return f"Domain '{primary_domain}' is on a threat intelligence blocklist."
    if feature_name == "ip_blacklisted":
        return (
            "Originating IP address has a high abuse confidence score on AbuseIPDB — "
            "this IP is associated with malicious activity."
        )
    if feature_name == "country_risk_score":
        return (
            "Originating IP is geolocated to a country frequently associated "
            "with phishing infrastructure."
        )
    if feature_name == "num_forms":
        return (
            f"{int(feature_value)} HTML form(s) in email body — "
            "forms embedded in emails are used to harvest credentials directly."
        )
    if feature_name == "display_name_brand_spoofing":
        display_name = context.get("display_name", "")
        display_brand = context.get("display_name_brand", "")
        sender_dom = context.get("sender", "")
        name_part = f'Display name "{display_name}" ' if display_name else "Display name "
        brand_part = f'contains brand keyword "{display_brand}" ' if display_brand else "contains a known brand keyword "
        return (
            f"{name_part}{brand_part}but the sending domain ({sender_dom}) is not a legitimate "
            f"{display_brand or 'brand'} domain — classic display-name spoofing to impersonate a trusted entity."
        )
    if feature_name == "webmail_phishing_phrase_count":
        matched = [p.split(":", 1)[1] for p in nlp_patterns if p.startswith("webmail:")][:5]
        kw = ", ".join(f'"{k}"' for k in matched) if matched else f"{int(feature_value)} occurrence(s)"
        return (
            f"Detected {int(feature_value)} webmail credential-harvesting phrase(s): {kw}. "
            "These phrases mimic IT helpdesk alerts to trick users into revealing email credentials."
        )
    if feature_name == "helpdesk_impersonation_detected":
        matched = [p.split(":", 1)[1] for p in nlp_patterns if p.startswith("helpdesk:")]
        phrase = f': "{matched[0]}"' if matched else ""
        return (
            f"IT helpdesk / administrator impersonation detected{phrase}. "
            "Attackers pose as internal IT staff to harvest credentials under the guise of support requests."
        )
    if feature_name == "generic_anchor_link_detected":
        matched = [p.split(":", 1)[1] for p in nlp_patterns if p.startswith("anchor:")]
        phrase = f': "{matched[0]}"' if matched else ""
        return (
            f"Generic phishing anchor text detected{phrase} — "
            'phrases like "click here", "login here", or "verify here" mask malicious destinations.'
        )

    return f"Value: {feature_value}"


def calculate_risk_score(features: Dict[str, float], context: Optional[Dict] = None) -> RiskScoringResult:
    """
    Calculate risk score using dual suspicion/trust buckets.

    risk_score = suspicion_score − trust_score  (clamped 0–100)
    """

    result = RiskScoringResult()
    ctx = context or {}

    suspicion_contributions: List[Tuple[str, float]] = []
    trust_contributions: List[Tuple[str, float]] = []

    # --- Suspicion bucket ---
    raw_suspicion = 0.0
    for feature_name, weight in SUSPICION_WEIGHTS.items():
        value = features.get(feature_name, 0.0)
        if value == 0.0:
            continue
        contribution = weight * value
        raw_suspicion += contribution
        suspicion_contributions.append((feature_name, contribution))

    # --- Trust bucket ---
    raw_trust = 0.0
    for feature_name, weight in TRUST_WEIGHTS.items():
        value = features.get(feature_name, 0.0)
        if value == 0.0:
            continue
        # Cap domain_age_days trust at 30 points
        contribution = weight * value
        if feature_name == "domain_age_days":
            contribution = min(contribution, 30.0)
        raw_trust += contribution
        trust_contributions.append((feature_name, -contribution))  # negative = reduces risk

    result.suspicion_score = round(raw_suspicion, 2)
    result.trust_score = round(raw_trust, 2)

    # §5: content-only protection — NLP signals alone cannot produce PHISHING
    non_content_suspicion = sum(
        c for name, c in suspicion_contributions
        if name not in CONTENT_ONLY_FEATURES
    )
    if non_content_suspicion == 0.0 and raw_suspicion > 0:
        # All suspicion is from content — cap effective score below PHISHING threshold
        raw_suspicion = min(raw_suspicion, 74.0)

    raw_score = raw_suspicion - raw_trust
    result.risk_score = max(0.0, min(100.0, raw_score))

    # §9: Updated verdict thresholds
    if result.risk_score >= 75:
        result.verdict = "PHISHING"
    elif result.risk_score >= 50:
        result.verdict = "SUSPICIOUS"
    elif result.risk_score >= 20:
        result.verdict = "MARKETING"
    else:
        result.verdict = "SAFE"

    # --- Indicators (suspicion signals only, sorted by severity) ---
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    for feature_name, contribution in suspicion_contributions:
        if contribution > 0:
            severity = SEVERITY_MAP.get(feature_name, "LOW")
            feature_value = features.get(feature_name, 0.0)
            detail = _build_detail(feature_name, feature_value, ctx)
            result.indicators.append({
                "indicator_type": feature_name,
                "severity": severity,
                "detail": detail,
                "confidence": min(abs(contribution) / 50.0, 1.0),
                "source_module": "risk_scorer",
            })

    result.indicators.sort(key=lambda x: severity_order.get(x["severity"], 4))

    # --- Top contributors (both suspicion + trust, for explainability) ---
    all_contributions = suspicion_contributions + trust_contributions
    all_contributions.sort(key=lambda x: abs(x[1]), reverse=True)
    result.top_contributors = [
        {
            "feature_name": name,
            "attribution_score": round(score, 2),
            "direction": "phishing" if score > 0 else "safe",
        }
        for name, score in all_contributions[:10]
    ]

    logger.debug(
        "risk_score_calculated",
        suspicion=result.suspicion_score,
        trust=result.trust_score,
        final=result.risk_score,
        verdict=result.verdict,
    )

    return result
