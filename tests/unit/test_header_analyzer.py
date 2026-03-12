"""
PhisMail — Header Analyzer Tests
"""

import pytest
from app.services.header_analysis.header_analyzer import (
    analyze_headers,
    HeaderAnalysisResult,
    _check_auth_result,
    _extract_domain,
)


class TestAnalyzeHeaders:
    """Test email header authentication and anomaly detection."""

    def test_detects_spf_fail(self, sample_headers):
        result = analyze_headers(
            headers=sample_headers,
            sender="attacker@evil.com",
            reply_to="phisher@malicious.net",
            return_path="<bounce@different.org>",
        )
        assert result.spf_pass is False

    def test_detects_dkim_fail(self, sample_headers):
        result = analyze_headers(
            headers=sample_headers,
            sender="attacker@evil.com",
            reply_to="phisher@malicious.net",
            return_path="<bounce@different.org>",
        )
        assert result.dkim_pass is False

    def test_detects_dmarc_fail(self, sample_headers):
        result = analyze_headers(
            headers=sample_headers,
            sender="attacker@evil.com",
            reply_to="phisher@malicious.net",
            return_path="<bounce@different.org>",
        )
        assert result.dmarc_pass is False

    def test_detects_reply_to_mismatch(self, sample_headers):
        result = analyze_headers(
            headers=sample_headers,
            sender="attacker@evil.com",
            reply_to="phisher@malicious.net",
            return_path="<bounce@different.org>",
        )
        assert result.reply_to_mismatch is True

    def test_detects_return_path_mismatch(self, sample_headers):
        result = analyze_headers(
            headers=sample_headers,
            sender="attacker@evil.com",
            reply_to="phisher@malicious.net",
            return_path="<bounce@different.org>",
        )
        assert result.return_path_mismatch is True

    def test_detects_sender_domain_mismatch(self, sample_headers):
        result = analyze_headers(
            headers=sample_headers,
            sender="attacker@evil.com",
            reply_to="phisher@malicious.net",
            return_path="<bounce@different.org>",
        )
        assert result.sender_domain_mismatch is True

    def test_no_mismatch_when_same_domain(self):
        headers = {
            "Authentication-Results": "mx.example.com; spf=pass; dkim=pass; dmarc=pass",
        }
        result = analyze_headers(
            headers=headers,
            sender="user@example.com",
            reply_to="user@example.com",
            return_path="<user@example.com>",
        )
        assert result.reply_to_mismatch is False
        assert result.return_path_mismatch is False
        assert result.spf_pass is True
        assert result.dkim_pass is True
        assert result.dmarc_pass is True

    def test_originating_ip_passthrough(self):
        result = analyze_headers(
            headers={},
            sender="x@y.com",
            reply_to=None,
            return_path=None,
            originating_ip="1.2.3.4",
        )
        assert result.originating_ip == "1.2.3.4"


class TestCheckAuthResult:
    """Test SPF/DKIM/DMARC result parsing."""

    def test_pass(self):
        assert _check_auth_result("spf=pass", "spf") is True

    def test_fail(self):
        assert _check_auth_result("spf=fail", "spf") is False

    def test_softfail(self):
        assert _check_auth_result("spf=softfail", "spf") is False

    def test_missing(self):
        assert _check_auth_result("", "spf") is None

    def test_none_header(self):
        assert _check_auth_result("", "dkim") is None


class TestExtractDomain:
    """Test email address domain extraction."""

    def test_simple_address(self):
        assert _extract_domain("user@example.com") == "example.com"

    def test_named_address(self):
        assert _extract_domain("John Doe <john@company.org>") == "company.org"

    def test_none_input(self):
        assert _extract_domain(None) is None

    def test_empty_string(self):
        assert _extract_domain("") is None
