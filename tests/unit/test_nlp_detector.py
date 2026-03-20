"""
PhisMail — NLP Phishing Language Detector Tests
"""

import pytest
from app.services.nlp_analysis.phishing_language_detector import (
    analyze_phishing_language,
    NlpAnalysisResult,
)


class TestAnalyzePhishingLanguage:
    """Test social engineering keyword detection."""

    def test_detects_urgency_keywords(self):
        result = analyze_phishing_language(
            subject="URGENT: Act now or your account will be suspended",
            body_text="This is your final notice. Failure to respond within 24 hours will result in closure.",
        )
        assert result.urgency_keyword_count >= 3

    def test_detects_credential_keywords(self):
        result = analyze_phishing_language(
            body_text="Please verify your account and enter your password to confirm your identity.",
        )
        assert result.credential_request_keywords >= 2

    def test_detects_financial_keywords(self):
        result = analyze_phishing_language(
            body_text="Your payment failed. Please update your billing information to avoid overdue charges.",
        )
        assert result.financial_request_keywords >= 2

    def test_detects_security_alert_keywords(self):
        result = analyze_phishing_language(
            body_text="Security alert: We detected unusual activity and unauthorized access on your account.",
        )
        assert result.security_alert_keywords >= 2

    def test_imperative_language_detection(self):
        result = analyze_phishing_language(
            body_text="Click here immediately. Download the attachment. Follow the link below.",
        )
        assert result.imperative_language_score > 0

    def test_threat_language_score_high_for_phishing(self):
        result = analyze_phishing_language(
            subject="URGENT: Security Alert - Unauthorized Access",
            body_text="Your account has been suspended. Verify your identity immediately or it will be terminated.",
        )
        assert result.threat_language_score > 0.3

    def test_clean_email_low_score(self):
        result = analyze_phishing_language(
            subject="Weekly Newsletter",
            body_text="Here are this week's top stories. Hope you enjoy the read.",
        )
        assert result.urgency_keyword_count == 0
        assert result.credential_request_keywords == 0
        assert result.threat_language_score == 0.0

    def test_html_body_analysis(self):
        result = analyze_phishing_language(
            body_html="<p>Your account is <b>locked</b>. <a href='#'>Click here</a> to verify your account.</p>",
        )
        assert result.urgency_keyword_count >= 1

    def test_handles_empty_input(self):
        result = analyze_phishing_language()
        assert result.urgency_keyword_count == 0
        assert result.threat_language_score == 0.0

    def test_detects_zero_width_char_evasion(self):
        """Zero-width characters inserted into keywords should be stripped."""
        # "ur\u200bgent" with zero-width space splitting "urgent"
        result = analyze_phishing_language(
            body_text="ur\u200bgent: act now or your account will be su\u200dspended",
        )
        assert result.urgency_keyword_count >= 2

    def test_detects_unicode_normalized_keywords(self):
        """NFKD normalization should catch fullwidth character evasion."""
        # Fullwidth "Ｕｒｇｅｎｔ" normalizes to "Urgent" under NFKD
        result = analyze_phishing_language(
            body_text="\uff35\uff52\uff47\uff45\uff4e\uff54: act now immediately",
        )
        assert result.urgency_keyword_count >= 1

    def test_detected_patterns_populated(self):
        result = analyze_phishing_language(
            body_text="Urgent! Verify your account immediately. Your payment has failed.",
        )
        assert len(result.detected_patterns) > 0
        assert any("urgency:" in p for p in result.detected_patterns)
