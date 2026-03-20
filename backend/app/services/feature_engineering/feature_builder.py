"""
PhisMail — Feature Builder
Aggregates all analysis signals into the feature engineering matrix.
Persists features to the feature store for ML retraining.
"""

from typing import Dict, Optional, Any, List
from datetime import datetime

from app.core.logging import get_logger

logger = get_logger(__name__)


def build_feature_vector(
    header_result: Optional[Any] = None,
    url_results: Optional[List[Any]] = None,
    domain_whois: Optional[Any] = None,
    domain_dns: Optional[Any] = None,
    threat_result: Optional[Any] = None,
    nlp_result: Optional[Any] = None,
    attachment_result: Optional[Any] = None,
    redirect_results: Optional[List[Any]] = None,
    homograph_result: Optional[Any] = None,
    ip_reputation_result: Optional[Any] = None,
    email_body_text: Optional[str] = None,
    email_body_html: Optional[str] = None,
    email_urls: Optional[List[str]] = None,
) -> Dict[str, float]:
    """Build the complete feature vector from all analysis results."""

    features: Dict[str, float] = {}

    # =========================================================================
    # 1. Email Header Features
    # =========================================================================
    if header_result:
        features["spf_pass"] = float(header_result.spf_pass is True)
        features["dkim_pass"] = float(header_result.dkim_pass is True)
        features["dmarc_pass"] = float(header_result.dmarc_pass is True)
        features["spf_fail"] = float(getattr(header_result, "spf_fail", False))
        features["dkim_fail"] = float(getattr(header_result, "dkim_fail", False))
        features["dmarc_fail"] = float(getattr(header_result, "dmarc_fail", False))
        features["authentication_all_pass"] = float(
            header_result.spf_pass is True
            and header_result.dkim_pass is True
            and header_result.dmarc_pass is True
        )
        features["bulk_mail_indicator"] = float(getattr(header_result, "bulk_mail_indicator", False))
        features["esp_detected"] = float(getattr(header_result, "esp_detected", False))
        features["reply_to_mismatch"] = float(header_result.reply_to_mismatch)
        features["return_path_mismatch"] = float(header_result.return_path_mismatch)
        features["sender_domain_mismatch"] = float(header_result.sender_domain_mismatch)
        features["originating_ip_present"] = float(header_result.originating_ip is not None)
        features["num_received_headers"] = float(header_result.num_received_headers)
        features["smtp_hops"] = float(header_result.smtp_hops)
        features["ip_private_network"] = 0.0
        # Display name brand spoofing (header-level signal)
        features["display_name_brand_spoofing"] = float(
            getattr(header_result, "display_name_brand_spoofing", False)
        )

    # =========================================================================
    # 2. URL Structural Features (12) — worst-case across ALL URLs
    # =========================================================================
    if url_results:
        # Suspicion = max across all URLs (any URL being suspicious matters)
        features["url_length"] = max(float(u.url_length) for u in url_results)
        features["num_dots"] = max(float(u.num_dots) for u in url_results)
        features["num_subdomains"] = max(float(u.num_subdomains) for u in url_results)
        features["num_hyphens"] = max(float(u.num_hyphens) for u in url_results)
        features["num_special_chars"] = max(float(u.num_special_chars) for u in url_results)
        features["contains_ip_address"] = max(float(u.contains_ip) for u in url_results)
        features["contains_at_symbol"] = max(float(u.contains_at_symbol) for u in url_results)
        features["num_query_parameters"] = max(float(u.num_query_parameters) for u in url_results)
        features["url_entropy_score"] = max(float(u.entropy_score) for u in url_results)
        features["num_fragments"] = max(float(u.num_fragments) for u in url_results)
        # has_https: min across all URLs (lack of HTTPS is suspicious)
        features["has_https"] = min(float(u.has_https) for u in url_results)
        features["url_shortened"] = max(float(u.is_shortened) for u in url_results)

    # =========================================================================
    # 3. URL Obfuscation Indicators (7) — worst-case across ALL URLs
    # =========================================================================
    if url_results:
        features["percent_encoding_count"] = max(float(u.percent_encoding_count) for u in url_results)
        features["hex_encoding_count"] = max(float(u.hex_encoding_count) for u in url_results)
        features["double_slash_redirect"] = max(float(u.double_slash_redirect) for u in url_results)
        features["encoded_characters_ratio"] = max(float(u.encoded_characters_ratio) for u in url_results)
        features["username_in_url"] = max(float(u.username_in_url) for u in url_results)
        features["mixed_case_domain"] = max(float(u.mixed_case_domain) for u in url_results)
        features["long_query_string"] = max(float(u.long_query_string) for u in url_results)

    # =========================================================================
    # 4. Domain Intelligence Features
    # =========================================================================
    if domain_whois:
        age = domain_whois.domain_age_days or 999
        features["domain_age_days"] = float(domain_whois.domain_age_days or -1)
        features["domain_very_recent"] = float(age < 7)
        features["domain_recent_registration"] = float(7 <= age < 30)
        features["domain_expiry_days"] = 0.0
        if domain_whois.expiry_date:
            delta = domain_whois.expiry_date - datetime.utcnow()
            features["domain_expiry_days"] = float(delta.days)
        features["domain_registrar_known"] = float(domain_whois.registrar is not None)
        features["num_nameservers"] = float(len(domain_whois.nameservers))

    if domain_dns:
        features["has_mx_record"] = float(domain_dns.has_mx_record)
        features["has_txt_record"] = float(len(domain_dns.txt_records) > 0)
        features["has_spf_record"] = float(domain_dns.has_spf_record)
        features["has_dmarc_record"] = float(domain_dns.has_dmarc_record)
        features["dns_record_count"] = float(domain_dns.dns_record_count)

    # =========================================================================
    # 5. Domain Reputation Features (5)
    # =========================================================================
    features.setdefault("tld_risk_score", 0.0)
    features.setdefault("domain_popularity_rank", 0.0)
    features.setdefault("asn_reputation_score", 0.0)
    features.setdefault("hosting_provider_known", 0.0)
    features["country_risk_score"] = (
        float(ip_reputation_result.country_risk_score)
        if ip_reputation_result else 0.0
    )

    # =========================================================================
    # 6. Threat Intelligence Features (6)
    # =========================================================================
    if threat_result:
        features["openphish_match"] = float(threat_result.openphish_match)
        features["phishtank_match"] = float(threat_result.phishtank_match)
        features["urlhaus_match"] = float(threat_result.urlhaus_match)
        features["domain_blacklisted"] = float(threat_result.domain_blacklisted)
        features["ip_blacklisted"] = (
            float(ip_reputation_result.ip_blacklisted)
            if ip_reputation_result else 0.0
        )
        features["threat_confidence_score"] = float(threat_result.confidence_score)

    # =========================================================================
    # 7. Redirect Behavior Features (5)
    # =========================================================================
    if redirect_results:
        primary_redirect = redirect_results[0] if redirect_results else None
        if primary_redirect:
            features["redirect_count"] = float(primary_redirect.redirect_count)
            features["redirect_to_different_domain"] = float(primary_redirect.redirect_to_different_domain)
            features["redirect_to_ip"] = float(primary_redirect.redirect_to_ip)
            features["final_domain_mismatch"] = float(primary_redirect.final_domain_mismatch)
            features["meta_refresh_detected"] = float(primary_redirect.meta_refresh_detected)

    # =========================================================================
    # 8. Social Engineering NLP Features (7)
    # =========================================================================
    if nlp_result:
        features["urgency_keyword_count"] = float(nlp_result.urgency_keyword_count)
        features["credential_request_keywords"] = float(nlp_result.credential_request_keywords)
        features["financial_request_keywords"] = float(nlp_result.financial_request_keywords)
        features["security_alert_keywords"] = float(nlp_result.security_alert_keywords)
        features["threat_language_score"] = float(nlp_result.threat_language_score)
        features["sentiment_score"] = float(nlp_result.sentiment_score)
        features["imperative_language_score"] = float(nlp_result.imperative_language_score)
        features["webmail_phishing_phrase_count"] = float(nlp_result.webmail_phishing_phrase_count)
        features["helpdesk_impersonation_detected"] = float(nlp_result.helpdesk_impersonation_detected)
        features["generic_anchor_link_detected"] = float(nlp_result.generic_anchor_link_detected)

    # =========================================================================
    # 9. Brand Impersonation Features
    # =========================================================================
    if homograph_result:
        brand = homograph_result.matched_brand
        features["brand_keyword_present"] = float(
            brand is not None
            or any(getattr(u, "brand_keyword_present", False) for u in (url_results or []))
        )
        features["brand_domain_similarity_score"] = float(homograph_result.similarity_score)
        features["brand_typosquat_distance"] = float(1.0 - homograph_result.similarity_score)
        features["brand_homograph_detected"] = float(homograph_result.is_homograph)

        # Contextual brand check: does the sender domain match the detected brand?
        sender_dom = getattr(header_result, "sender_domain", None) if header_result else None
        if brand and sender_dom:
            import tldextract as _tld
            sender_root = _tld.extract(sender_dom if "." in sender_dom else f"x.{sender_dom}").domain.lower()
            brand_match = brand.lower() == sender_root
            features["brand_sender_domain_match"] = float(brand_match)
            features["brand_sender_domain_mismatch"] = float(not brand_match)
        else:
            features["brand_sender_domain_match"] = 0.0
            features["brand_sender_domain_mismatch"] = float(brand is not None)

    # URL domain vs sender domain consistency — worst-case across ALL URLs
    CDN_DOMAINS = {
        "cloudfront.net", "akamai.net", "akamaized.net", "fastly.net",
        "cdn.shopify.com", "cdn.jsdelivr.net", "cloudflare.com",
        "azureedge.net", "amazonaws.com", "googleusercontent.com",
    }
    if url_results and header_result:
        import tldextract as _tld
        sender_dom = getattr(header_result, "sender_domain", "") or ""

        any_unrelated = False
        any_cdn = False
        any_subdomain = False
        any_match = False

        for u in url_results:
            url_domain = (u.domain or "")
            if not url_domain:
                continue
            if sender_dom:
                url_extracted = _tld.extract(url_domain)
                url_root = url_extracted.domain.lower()
                url_suffix = url_extracted.suffix.lower()
                url_registered = f"{url_root}.{url_suffix}"
                sender_extracted = _tld.extract(sender_dom if "." in sender_dom else f"x.{sender_dom}")
                sender_root = sender_extracted.domain.lower()
                sender_suffix = sender_extracted.suffix.lower()
                sender_registered = f"{sender_root}.{sender_suffix}"

                domains_match = bool(url_root and sender_root and (url_root == sender_root or url_root in sender_root or sender_root in url_root))
                if domains_match:
                    any_match = True
                else:
                    any_unrelated = True

                is_subdomain_of_sender = (
                    url_registered == sender_registered
                    or url_domain.endswith(f".{sender_registered}")
                )
                if is_subdomain_of_sender:
                    any_subdomain = True

            is_cdn = any(url_domain == cdn or url_domain.endswith(f".{cdn}") for cdn in CDN_DOMAINS)
            if is_cdn:
                any_cdn = True

        # Worst-case: if ANY URL is unrelated, flag it
        features["url_domain_matches_sender"] = float(any_match and not any_unrelated)
        features["url_domain_unrelated_to_sender"] = float(any_unrelated)
        features["url_domain_subdomain_of_sender"] = float(any_subdomain)
        features["url_domain_cdn"] = float(any_cdn)
    elif url_results:
        # URL present but no sender domain — check CDN only
        import tldextract as _tld
        any_cdn = any(
            any((u.domain or "") == cdn or (u.domain or "").endswith(f".{cdn}") for cdn in CDN_DOMAINS)
            for u in url_results
        )
        features["url_domain_cdn"] = float(any_cdn)
        features.setdefault("url_domain_matches_sender", 0.0)
        features.setdefault("url_domain_unrelated_to_sender", 0.0)
        features.setdefault("url_domain_subdomain_of_sender", 0.0)

    # =========================================================================
    # 10. Attachment Risk Features (7)
    # =========================================================================
    if attachment_result:
        features["attachment_count"] = float(attachment_result.attachment_count)
        features["has_executable_attachment"] = float(attachment_result.has_executable)
        features["has_script_attachment"] = float(attachment_result.has_script)
        features["has_macro_document"] = float(attachment_result.has_macro_document)
        features["double_extension_detected"] = float(attachment_result.double_extension_detected)
        features["archive_with_executable"] = float(attachment_result.archive_with_executable)
        features["mime_mismatch_detected"] = float(attachment_result.mime_mismatch_detected)

    # =========================================================================
    # 11. Email Structure Features (7)
    # =========================================================================
    features["num_urls_in_email"] = float(len(email_urls or []))
    features["num_external_domains"] = float(
        len(set(getattr(u, "domain", "") for u in (url_results or []) if getattr(u, "domain", "")))
    )
    if email_body_html and email_body_text:
        html_len = len(email_body_html)
        text_len = len(email_body_text) if email_body_text else 1
        features["html_to_text_ratio"] = float(html_len / max(text_len, 1))
    else:
        features["html_to_text_ratio"] = 0.0
    features["num_images"] = 0.0
    features["num_forms"] = 0.0
    features["javascript_in_email"] = 0.0
    features["hidden_links_detected"] = 0.0

    if email_body_html:
        import re
        num_images = len(re.findall(r"<img\s", email_body_html, re.IGNORECASE))
        features["num_images"] = float(num_images)
        features["num_forms"] = float(len(re.findall(r"<form\s", email_body_html, re.IGNORECASE)))
        features["javascript_in_email"] = float(
            1 if re.search(r"<script|javascript:", email_body_html, re.IGNORECASE) else 0
        )
        features["hidden_links_detected"] = float(
            1 if re.search(r'display\s*:\s*none|visibility\s*:\s*hidden', email_body_html, re.IGNORECASE) else 0
        )
        # Marketing template signals
        has_unsubscribe = bool(re.search(r'unsubscribe', email_body_html, re.IGNORECASE))
        has_tracking_pixel = bool(re.search(
            r'<img[^>]+(?:width=["\']?1["\']?[^>]+height=["\']?1["\']?|height=["\']?1["\']?[^>]+width=["\']?1["\']?)',
            email_body_html, re.IGNORECASE,
        ))
        features["has_unsubscribe_link"] = float(has_unsubscribe)
        features["has_tracking_pixel"] = float(has_tracking_pixel)
        features["marketing_template_signals"] = float(has_unsubscribe or has_tracking_pixel or num_images >= 3)
    else:
        features.setdefault("has_unsubscribe_link", 0.0)
        features.setdefault("has_tracking_pixel", 0.0)
        features.setdefault("marketing_template_signals", 0.0)

    # =========================================================================
    # 12. Temporal Features (3)
    # =========================================================================
    features.setdefault("domain_age_hours", 0.0)
    if domain_whois and domain_whois.domain_age_days:
        features["domain_age_hours"] = float(domain_whois.domain_age_days * 24)
    features["email_sent_outside_business_hours"] = 0.0
    features["campaign_activity_frequency"] = 0.0

    return features
