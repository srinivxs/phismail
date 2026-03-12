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


class MockAttachmentResult:
    def __init__(self):
        self.attachment_count = 1
        self.has_executable = True
        self.has_script = False
        self.has_macro_document = False
        self.double_extension_detected = True
        self.archive_with_executable = False
        self.mime_mismatch_detected = False


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

    def test_feature_count_in_expected_range(self):
        """Feature vector should have ~70-90 features."""
        features = build_feature_vector(
            header_result=MockHeaderResult(),
            url_results=[MockUrlResult()],
            nlp_result=MockNlpResult(),
            attachment_result=MockAttachmentResult(),
        )
        assert len(features) >= 40, f"Only {len(features)} features, expected 40+"
