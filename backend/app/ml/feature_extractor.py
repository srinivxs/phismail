"""
PhisMail — Email Feature Extractor
Extracts 35+ features from raw email data for ML classification.
Optimized for low false-positive rate with authentication-first approach.
"""

import re
from urllib.parse import urlparse
from typing import Dict, List, Any

import tldextract

from app.core.logging import get_logger

logger = get_logger(__name__)


class EmailFeatureExtractor:
    """Extract features from parsed email data for ML classification.

    Focus: Authentication signals first, domain/URL structural analysis second,
    content analysis third. This ordering minimizes false positives by giving
    strong weight to verifiable infrastructure signals.
    """

    def __init__(self) -> None:
        self.known_esps = {
            "sendgrid.net", "sendgrid.com", "mailgun.org", "mailgun.com",
            "mailchimp.com", "mcsv.net", "mktomail.com", "exacttarget.com",
            "hs-email.net", "hubspot.com", "amazonses.com", "sparkpost.com",
            "mandrill.com", "ncdelivery", "netcorecloud", "pepipost.com",
            "mailjet.com", "sendinblue.com", "postmarkapp.com",
        }

        self.known_brands = {
            "google.com", "microsoft.com", "apple.com", "amazon.com",
            "netflix.com", "paypal.com", "facebook.com", "instagram.com",
            "linkedin.com", "twitter.com", "github.com", "stackoverflow.com",
        }

        self.suspicious_tlds = {
            ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work",
            ".click", ".link", ".download", ".stream", ".icu",
        }

        self.high_urgency_keywords = {
            "verify", "suspend", "suspended", "account", "urgent", "immediate",
            "expire", "expired", "expiring", "security", "unauthorized",
            "confirm", "update", "validate", "locked", "unusual", "activity",
            "detected", "click here", "act now", "limited time",
        }

        self.marketing_keywords = {
            "sale", "offer", "discount", "deal", "alert", "new", "collection",
            "exclusive", "shop", "save", "newsletter", "unsubscribe",
        }

        self.url_shorteners = {
            "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "buff.ly",
            "is.gd", "tiny.cc", "short.io", "rebrand.ly",
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract_all_features(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract all features from parsed email data.

        Args:
            email_data: Dict with keys like ``from``, ``subject``,
                ``body_text``, ``authentication_results``, ``urls``, etc.

        Returns:
            Dict of 35+ numeric features for ML model input.
        """
        features: Dict[str, Any] = {}
        features.update(self._extract_auth_features(email_data))
        features.update(self._extract_domain_features(email_data))
        features.update(self._extract_url_features(email_data))
        features.update(self._extract_content_features(email_data))
        features.update(self._extract_header_features(email_data))
        return features

    # ------------------------------------------------------------------
    # Category 1: Authentication (5 features)
    # ------------------------------------------------------------------

    def _extract_auth_features(self, email_data: Dict) -> Dict[str, int]:
        auth_results = email_data.get("authentication_results", "").lower()

        spf_pass = 1 if "spf=pass" in auth_results else 0
        dkim_pass = 1 if "dkim=pass" in auth_results else 0
        dmarc_pass = 1 if "dmarc=pass" in auth_results else 0

        return {
            "spf_pass": spf_pass,
            "dkim_pass": dkim_pass,
            "dmarc_pass": dmarc_pass,
            "all_auth_pass": 1 if (spf_pass and dkim_pass and dmarc_pass) else 0,
            "auth_score": spf_pass + dkim_pass + dmarc_pass,
        }

    # ------------------------------------------------------------------
    # Category 2: Domain (8 features)
    # ------------------------------------------------------------------

    def _extract_domain_features(self, email_data: Dict) -> Dict[str, Any]:
        from_addr = email_data.get("from", "")
        return_path = email_data.get("return_path", "")

        from_domain = self._extract_domain(from_addr)
        return_path_domain = self._extract_domain(return_path)

        from_ext = tldextract.extract(from_domain)
        return_ext = tldextract.extract(return_path_domain)

        domain_exact_match = 1 if from_domain == return_path_domain else 0

        from_base = f"{from_ext.domain}.{from_ext.suffix}" if from_ext.domain else ""
        return_base = f"{return_ext.domain}.{return_ext.suffix}" if return_ext.domain else ""
        base_domain_match = 1 if from_base == return_base else 0

        is_known_esp = 1 if self._is_known_esp(return_path_domain) else 0
        esp_aligned = 1 if from_base in return_path_domain else 0
        is_known_brand = 1 if self._is_known_brand(from_domain) else 0

        from_subdomain_depth = len(from_ext.subdomain.split(".")) if from_ext.subdomain else 0
        domain_length = len(from_domain)
        has_suspicious_tld = 1 if any(from_domain.endswith(tld) for tld in self.suspicious_tlds) else 0

        return {
            "domain_exact_match": domain_exact_match,
            "base_domain_match": base_domain_match,
            "is_known_esp": is_known_esp,
            "esp_aligned": esp_aligned,
            "is_known_brand": is_known_brand,
            "from_subdomain_depth": from_subdomain_depth,
            "domain_length": min(domain_length, 100),
            "has_suspicious_tld": has_suspicious_tld,
        }

    # ------------------------------------------------------------------
    # Category 3: URL (8 features)
    # ------------------------------------------------------------------

    def _extract_url_features(self, email_data: Dict) -> Dict[str, Any]:
        urls = email_data.get("urls", [])

        if not urls:
            return {
                "total_urls": 0, "http_count": 0, "https_count": 0,
                "http_ratio": 0.0, "has_url_shortener": 0,
                "has_ip_in_url": 0, "external_domains_count": 0,
                "max_url_length": 0,
            }

        http_count = sum(1 for url in urls if url.startswith("http://"))
        https_count = sum(1 for url in urls if url.startswith("https://"))
        total_urls = len(urls)
        http_ratio = http_count / total_urls if total_urls > 0 else 0

        has_shortener = 1 if any(
            any(shortener in url for shortener in self.url_shorteners)
            for url in urls
        ) else 0

        ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        has_ip = 1 if any(re.search(ip_pattern, url) for url in urls) else 0

        domains = set()
        for url in urls:
            parsed = urlparse(url)
            if parsed.netloc:
                domains.add(parsed.netloc)

        from_domain = self._extract_domain(email_data.get("from", ""))
        from_base = tldextract.extract(from_domain)
        from_base_domain = f"{from_base.domain}.{from_base.suffix}" if from_base.domain else ""

        external_domains = sum(
            1 for domain in domains if from_base_domain not in domain
        )

        max_url_length = max(len(url) for url in urls) if urls else 0

        return {
            "total_urls": min(total_urls, 50),
            "http_count": min(http_count, 50),
            "https_count": min(https_count, 50),
            "http_ratio": http_ratio,
            "has_url_shortener": has_shortener,
            "has_ip_in_url": has_ip,
            "external_domains_count": min(external_domains, 20),
            "max_url_length": min(max_url_length, 500),
        }

    # ------------------------------------------------------------------
    # Category 4: Content (8 features)
    # ------------------------------------------------------------------

    def _extract_content_features(self, email_data: Dict) -> Dict[str, Any]:
        subject = email_data.get("subject", "").lower()
        body = email_data.get("body_text", "").lower()

        subject_length = len(subject)
        has_re_fwd = 1 if subject.startswith(("re:", "fwd:", "fw:")) else 0

        high_urgency_count = sum(
            1 for kw in self.high_urgency_keywords
            if kw in subject or kw in body[:500]
        )

        marketing_keyword_count = sum(
            1 for kw in self.marketing_keywords
            if kw in subject or kw in body[:500]
        )

        special_char_count = sum(1 for c in subject if not c.isalnum() and c != " ")
        special_char_ratio = special_char_count / len(subject) if subject else 0

        body_length = len(body)

        html_body = email_data.get("body_html", "")
        html_to_text_ratio = len(html_body) / max(len(body), 1) if html_body else 1.0

        has_attachments = 1 if email_data.get("attachments", []) else 0

        return {
            "subject_length": min(subject_length, 200),
            "has_re_fwd": has_re_fwd,
            "high_urgency_count": min(high_urgency_count, 10),
            "marketing_keyword_count": min(marketing_keyword_count, 10),
            "special_char_ratio": special_char_ratio,
            "body_length": min(body_length, 10000),
            "html_to_text_ratio": min(html_to_text_ratio, 10.0),
            "has_attachments": has_attachments,
        }

    # ------------------------------------------------------------------
    # Category 5: Header (6 features)
    # ------------------------------------------------------------------

    def _extract_header_features(self, email_data: Dict) -> Dict[str, int]:
        from_addr = email_data.get("from", "")
        reply_to = email_data.get("reply_to", "")

        has_display_name = 1 if "<" in from_addr else 0
        reply_to_mismatch = 1 if (reply_to and reply_to != from_addr) else 0
        received_count = len(email_data.get("received_headers", []))
        has_message_id = 1 if email_data.get("message_id") else 0
        has_mailer = 1 if email_data.get("x_mailer") else 0
        has_unsubscribe = 1 if email_data.get("list_unsubscribe") else 0

        return {
            "has_display_name": has_display_name,
            "reply_to_mismatch": reply_to_mismatch,
            "received_count": min(received_count, 20),
            "has_message_id": has_message_id,
            "has_mailer": has_mailer,
            "has_unsubscribe": has_unsubscribe,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extract_domain(self, email_or_url: str) -> str:
        if "@" in email_or_url:
            match = re.search(r"@([^\s>]+)", email_or_url)
            return match.group(1).lower() if match else ""
        parsed = urlparse(
            email_or_url if "://" in email_or_url else f"http://{email_or_url}"
        )
        return parsed.netloc.lower()

    def _is_known_esp(self, domain: str) -> bool:
        domain_lower = domain.lower()
        return any(esp in domain_lower for esp in self.known_esps)

    def _is_known_brand(self, domain: str) -> bool:
        ext = tldextract.extract(domain)
        base_domain = f"{ext.domain}.{ext.suffix}" if ext.domain else domain.lower()
        return base_domain in self.known_brands

    def update_known_brands(self, brands: List[str]) -> None:
        self.known_brands.update(b.lower() for b in brands)

    def update_known_esps(self, esps: List[str]) -> None:
        self.known_esps.update(e.lower() for e in esps)
