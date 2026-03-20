"""
PhisMail — Feature Builder Tests
"""

import pytest
from app.services.feature_engineering.feature_builder import build_feature_vector


class MockHeaderResult:
    def __init__(self):
        self.spf_pass = False
        self.dkim_pass = False
        self.dmarc_pass = False
        self.reply_to_mismatch = True
        self.return_path_mismatch = True
        self.sender_domain_mismatch = True
        self.originating_ip = "1.2.3.4"
        self.num_received_headers = 5
        self.smtp_hops = 5


class MockUrlResult:
    def __init__(self):
        self.url = "https://phish.com/login"
        self.domain = "phish.com"
        self.tld = ".com"
        self.url_length = 25
        self.num_dots = 2
        self.num_subdomains = 0
        self.num_hyphens = 0
        self.num_special_chars = 3
        self.contains_ip = False
        self.contains_at_symbol = False
        self.num_query_parameters = 0
        self.entropy_score = 4.2
        self.num_fragments = 0
        self.has_https = True
        self.is_shortened = False
        self.percent_encoding_count = 0
        self.hex_encoding_count = 0
        self.double_slash_redirect = False
        self.encoded_characters_ratio = 0.0
        self.username_in_url = False
        self.mixed_case_domain = False
        self.long_query_string = False
        self.brand_keyword_present = False


class MockNlpResult:
    def __init__(self):
        self.urgency_keyword_count = 5
        self.credential_request_keywords = 2
        self.financial_request_keywords = 1
        self.security_alert_keywords = 3
        self.threat_language_score = 0.8
        self.sentiment_score = 0.6
        self.imperative_language_score = 0.4
        self.webmail_phishing_phrase_count = 0
        self.helpdesk_impersonation_detected = False
        self.generic_anchor_link_detected = False


class MockAttachmentResult:
    def __init__(self):
        self.attachment_count = 1
        self.has_executable = True
        self.has_script = False
        self.has_macro_document = False
        self.double_extension_detected = True
        self.archive_with_executable = False
        self.mime_mismatch_detected = False


class MockRedirectResult:
    def __init__(self, count=3, different_domain=True, to_ip=False,
                 domain_mismatch=True, meta_refresh=True):
        self.redirect_count = count
        self.redirect_to_different_domain = different_domain
        self.redirect_to_ip = to_ip
        self.final_domain_mismatch = domain_mismatch
        self.meta_refresh_detected = meta_refresh


class MockThreatIntelResult:
    def __init__(self, openphish=False, phishtank=True, urlhaus=False):
        self.openphish_match = openphish
        self.phishtank_match = phishtank
        self.urlhaus_match = urlhaus
        self.domain_blacklisted = any([openphish, phishtank, urlhaus])
        self.confidence_score = sum([openphish, phishtank, urlhaus]) / 3.0
        self.matches = []


class TestBuildFeatureVector:
    """Test feature vector aggregation."""

    def test_builds_header_features(self):
        features = build_feature_vector(header_result=MockHeaderResult())
        assert features["spf_pass"] == 0.0
        assert features["reply_to_mismatch"] == 1.0
        assert features["smtp_hops"] == 5.0

    def test_builds_url_features(self):
        features = build_feature_vector(url_results=[MockUrlResult()])
        assert features["url_length"] == 25.0
        assert features["has_https"] == 1.0
        assert features["url_shortened"] == 0.0

    def test_builds_nlp_features(self):
        features = build_feature_vector(nlp_result=MockNlpResult())
        assert features["urgency_keyword_count"] == 5.0
        assert features["threat_language_score"] == 0.8

    def test_builds_attachment_features(self):
        features = build_feature_vector(attachment_result=MockAttachmentResult())
        assert features["has_executable_attachment"] == 1.0
        assert features["double_extension_detected"] == 1.0

    def test_builds_email_structure_features(self):
        features = build_feature_vector(
            email_body_text="Simple text",
            email_body_html='<html><body><form action=""><input></form><img src="x"></body></html>',
            email_urls=["https://a.com", "https://b.com"],
        )
        assert features["num_urls_in_email"] == 2.0
        assert features["num_forms"] >= 1.0
        assert features["num_images"] >= 1.0

    def test_html_analysis_detects_javascript(self):
        features = build_feature_vector(
            email_body_html="<html><script>alert('xss')</script></html>",
        )
        assert features["javascript_in_email"] == 1.0

    def test_html_analysis_detects_hidden_links(self):
        features = build_feature_vector(
            email_body_html='<html><div style="display:none"><a href="x">hidden</a></div></html>',
        )
        assert features["hidden_links_detected"] == 1.0

    def test_empty_input_returns_defaults(self):
        features = build_feature_vector()
        assert "html_to_text_ratio" in features
        assert features["num_urls_in_email"] == 0.0

    def test_all_features_are_floats(self):
        features = build_feature_vector(
            header_result=MockHeaderResult(),
            url_results=[MockUrlResult()],
            nlp_result=MockNlpResult(),
            attachment_result=MockAttachmentResult(),
        )
        for key, value in features.items():
            assert isinstance(value, float), f"Feature '{key}' is {type(value)}, not float"

    def test_builds_threat_intel_features(self):
        """Threat intel results should map into the feature vector."""
        threat = MockThreatIntelResult(openphish=True, phishtank=True, urlhaus=False)
        features = build_feature_vector(threat_result=threat)
        assert features["openphish_match"] == 1.0
        assert features["phishtank_match"] == 1.0
        assert features["urlhaus_match"] == 0.0
        assert features["domain_blacklisted"] == 1.0
        assert abs(features["threat_confidence_score"] - (2 / 3.0)) < 0.01

    def test_threat_intel_absent_leaves_no_features(self):
        """When threat_result is None, threat intel features should not be set."""
        features = build_feature_vector()
        assert "openphish_match" not in features
        assert "phishtank_match" not in features

    def test_builds_redirect_features(self):
        """Redirect chain results should map into the feature vector."""
        redirect = MockRedirectResult(
            count=3, different_domain=True, to_ip=False,
            domain_mismatch=True, meta_refresh=True,
        )
        features = build_feature_vector(redirect_results=[redirect])
        assert features["redirect_count"] == 3.0
        assert features["redirect_to_different_domain"] == 1.0
        assert features["redirect_to_ip"] == 0.0
        assert features["final_domain_mismatch"] == 1.0
        assert features["meta_refresh_detected"] == 1.0

    def test_redirect_absent_leaves_no_features(self):
        """When redirect_results is empty, redirect features should not be set."""
        features = build_feature_vector(redirect_results=[])
        assert "redirect_count" not in features
        assert "final_domain_mismatch" not in features

    def test_worst_url_scoring_uses_most_suspicious(self):
        """When multiple URLs exist, worst-case values should be used."""
        benign = MockUrlResult()
        benign.url_length = 20
        benign.contains_ip = False
        benign.has_https = True
        benign.entropy_score = 2.0
        benign.username_in_url = False
        benign.is_shortened = False

        malicious = MockUrlResult()
        malicious.url_length = 150
        malicious.contains_ip = True
        malicious.has_https = False
        malicious.entropy_score = 6.5
        malicious.username_in_url = True
        malicious.is_shortened = True

        features = build_feature_vector(url_results=[benign, malicious])

        # max() for suspicion features
        assert features["url_length"] == 150.0
        assert features["contains_ip_address"] == 1.0
        assert features["url_entropy_score"] == 6.5
        assert features["username_in_url"] == 1.0
        assert features["url_shortened"] == 1.0
        # min() for has_https (lack of HTTPS is suspicious)
        assert features["has_https"] == 0.0

    def test_worst_url_order_independent(self):
        """Worst-case scoring should not depend on URL order."""
        benign = MockUrlResult()
        benign.url_length = 20
        benign.contains_ip = False

        malicious = MockUrlResult()
        malicious.url_length = 150
        malicious.contains_ip = True

        # malicious first
        f1 = build_feature_vector(url_results=[malicious, benign])
        # benign first (old code would miss malicious)
        f2 = build_feature_vector(url_results=[benign, malicious])

        assert f1["url_length"] == f2["url_length"] == 150.0
        assert f1["contains_ip_address"] == f2["contains_ip_address"] == 1.0

    def test_ip_reputation_wired_into_features(self):
        """IP reputation result should populate ip_blacklisted and country_risk_score."""

        class MockIpReputation:
            ip_blacklisted = True
            country_risk_score = 1.0

        threat = MockThreatIntelResult()
        features = build_feature_vector(
            threat_result=threat,
            ip_reputation_result=MockIpReputation(),
        )
        assert features["ip_blacklisted"] == 1.0
        assert features["country_risk_score"] == 1.0

    def test_ip_reputation_absent_defaults_to_zero(self):
        """Without IP reputation, ip_blacklisted and country_risk_score should be 0."""
        threat = MockThreatIntelResult()
        features = build_feature_vector(threat_result=threat)
        assert features["ip_blacklisted"] == 0.0
        assert features["country_risk_score"] == 0.0

    def test_feature_count_in_expected_range(self):
        """Feature vector should have ~70-90 features."""
        features = build_feature_vector(
            header_result=MockHeaderResult(),
            url_results=[MockUrlResult()],
            nlp_result=MockNlpResult(),
            attachment_result=MockAttachmentResult(),
        )
        assert len(features) >= 40, f"Only {len(features)} features, expected 40+"
