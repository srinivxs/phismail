"""
PhisMail — Phishing Language Detector
Regex-based NLP for detecting social engineering patterns in email text.
"""

import re
from typing import Optional

from app.core.logging import get_logger

logger = get_logger(__name__)

# =============================================================================
# Keyword Dictionaries
# =============================================================================

URGENCY_KEYWORDS = [
    "urgent", "immediately", "right away", "as soon as possible", "asap",
    "expire", "expired", "suspend", "suspended", "deactivate", "deactivated",
    "lock", "locked", "close", "closing", "terminate", "terminated",
    "within 24 hours", "within 48 hours", "limited time", "act now",
    "do not ignore", "failure to", "final notice", "last warning",
    "important notice", "time sensitive", "action required",
]

CREDENTIAL_KEYWORDS = [
    "verify your account", "confirm your identity", "update your information",
    "enter your password", "login credentials", "sign in",
    "username and password", "social security", "ssn",
    "credit card number", "bank account", "routing number",
    "reset your password", "verify your email", "confirm your email",
    "update your payment", "billing information",
]

FINANCIAL_KEYWORDS = [
    "wire transfer", "payment", "invoice", "refund", "transaction",
    "outstanding balance", "overdue", "pay now", "payment failed",
    "unauthorized transaction", "suspicious activity on your account",
    "claim your reward", "you have won", "prize", "lottery",
    "inheritance", "beneficiary", "million dollars",
]

SECURITY_ALERT_KEYWORDS = [
    "security alert", "security notice", "unusual activity",
    "unauthorized access", "suspicious login", "account compromised",
    "data breach", "security update", "verify your identity",
    "unusual sign-in", "someone accessed your account",
    "your account has been", "we detected",
]

IMPERATIVE_PATTERNS = [
    r"\bclick[\s:]+here\b",
    r"\bclick\s+(?:below|the\s+link)\b",
    r"\bkindly\s+click\b",
    r"\bdownload\s+(?:the|this)\b",
    r"\bopen\s+(?:the|this)\b",
    r"\bfollow\s+(?:the|this)\b",
    r"\bvisit\s+(?:the|this)\b",
    r"\breply\s+(?:with|to)\b",
]

# Webmail credential-harvesting phrases
WEBMAIL_PHISHING_PHRASES = [
    "pending email", "pending messages", "pending status", "pending mail",
    "verify your mailbox", "upgrade your mailbox", "mailbox upgrade",
    "mailbox alert", "mailbox quota", "mailbox full",
    "login with your webmail", "webmail information", "webmail credentials",
    "reconfirm your account", "incoming mail", "database upgrade",
    "placed on pending", "incoming mails were placed",
    "in order to receive", "kindly click",
]

# IT helpdesk / administrator impersonation phrases
HELPDESK_IMPERSONATION_PHRASES = [
    "helpdesk administrator", "helpdesk team", "helpdesk support",
    "mailbox administrator", "mail administrator", "email administrator",
    "it support team", "it administrator", "network administrator",
    "system administrator team", "technical support team",
    "administrator team",
]

# Generic anchor text in plain-text phishing emails
GENERIC_ANCHOR_PATTERNS = [
    r"\bclick[\s:]+here\b",
    r"\bhere\s+(?:to\s+)?(?:login|verify|access|confirm|update)\b",
    r"\blogin\s+here\b",
    r"\bverify\s+here\b",
    r"\baccess\s+here\b",
    r"\bclick\s+the\s+link\s+(?:below|above)\b",
]


class NlpAnalysisResult:
    """Result of NLP phishing language analysis."""

    def __init__(self):
        self.urgency_keyword_count: int = 0
        self.credential_request_keywords: int = 0
        self.financial_request_keywords: int = 0
        self.security_alert_keywords: int = 0
        self.threat_language_score: float = 0.0
        self.sentiment_score: float = 0.0  # 0 = neutral, 1 = highly threatening
        self.imperative_language_score: float = 0.0
        self.webmail_phishing_phrase_count: int = 0
        self.helpdesk_impersonation_detected: bool = False
        self.generic_anchor_link_detected: bool = False
        self.detected_patterns: list = []


def analyze_phishing_language(
    subject: Optional[str] = None,
    body_text: Optional[str] = None,
    body_html: Optional[str] = None,
) -> NlpAnalysisResult:
    """Analyze email text for social engineering language patterns."""

    result = NlpAnalysisResult()

    # Combine text sources
    combined = ""
    if subject:
        combined += subject + " "
    if body_text:
        combined += body_text + " "
    if body_html:
        # Strip HTML tags for text analysis
        combined += re.sub(r"<[^>]+>", " ", body_html)

    if not combined.strip():
        return result

    text_lower = combined.lower()

    # Count urgency keywords
    for keyword in URGENCY_KEYWORDS:
        count = text_lower.count(keyword)
        if count > 0:
            result.urgency_keyword_count += count
            result.detected_patterns.append(f"urgency:{keyword}")

    # Count credential harvesting keywords
    for keyword in CREDENTIAL_KEYWORDS:
        count = text_lower.count(keyword)
        if count > 0:
            result.credential_request_keywords += count
            result.detected_patterns.append(f"credential:{keyword}")

    # Count financial keywords
    for keyword in FINANCIAL_KEYWORDS:
        count = text_lower.count(keyword)
        if count > 0:
            result.financial_request_keywords += count
            result.detected_patterns.append(f"financial:{keyword}")

    # Count security alert keywords
    for keyword in SECURITY_ALERT_KEYWORDS:
        count = text_lower.count(keyword)
        if count > 0:
            result.security_alert_keywords += count
            result.detected_patterns.append(f"security:{keyword}")

    # Imperative language detection
    imperative_count = 0
    for pattern in IMPERATIVE_PATTERNS:
        matches = re.findall(pattern, text_lower)
        imperative_count += len(matches)
    result.imperative_language_score = min(imperative_count / 5.0, 1.0)

    # Webmail credential-harvesting phrases
    for phrase in WEBMAIL_PHISHING_PHRASES:
        count = text_lower.count(phrase)
        if count > 0:
            result.webmail_phishing_phrase_count += count
            result.detected_patterns.append(f"webmail:{phrase}")

    # Helpdesk / administrator impersonation
    for phrase in HELPDESK_IMPERSONATION_PHRASES:
        if phrase in text_lower:
            result.helpdesk_impersonation_detected = True
            result.detected_patterns.append(f"helpdesk:{phrase}")
            break

    # Generic anchor link patterns in plain text
    for pattern in GENERIC_ANCHOR_PATTERNS:
        if re.search(pattern, text_lower):
            result.generic_anchor_link_detected = True
            result.detected_patterns.append("anchor:generic_link")
            break

    # Calculate composite scores
    total_signals = (
        result.urgency_keyword_count
        + result.credential_request_keywords
        + result.financial_request_keywords
        + result.security_alert_keywords
    )

    result.threat_language_score = min(total_signals / 10.0, 1.0)
    result.sentiment_score = min(
        (result.urgency_keyword_count * 0.3 + result.security_alert_keywords * 0.4
         + result.credential_request_keywords * 0.3) / 5.0,
        1.0,
    )

    return result
