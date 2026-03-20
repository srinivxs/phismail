"""
PhisMail — Header Analyzer Tests
"""

import pytest
from unittest.mock import patch, MagicMock
from app.services.header_analysis.header_analyzer import (
    analyze_headers,
    HeaderAnalysisResult,
    validate_spf_live,
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


class TestValidateSpfLive:
    """Test live SPF DNS validation."""

    def test_returns_none_without_ip(self):
        assert validate_spf_live(None, "example.com") is None

    def test_returns_none_without_domain(self):
        assert validate_spf_live("1.2.3.4", None) is None

    def test_returns_none_without_both(self):
        assert validate_spf_live(None, None) is None

    def test_returns_true_on_pass(self):
        mock_spf = MagicMock()
        mock_spf.check.return_value = ("pass", 250, "sender is authorized")
        with patch.dict("sys.modules", {"spf": mock_spf}):
            assert validate_spf_live("1.2.3.4", "example.com") is True
            mock_spf.check.assert_called_once_with(
                i="1.2.3.4", s="postmaster@example.com", h="example.com"
            )

    def test_returns_false_on_fail(self):
        mock_spf = MagicMock()
        mock_spf.check.return_value = ("fail", 550, "not authorized")
        with patch.dict("sys.modules", {"spf": mock_spf}):
            assert validate_spf_live("1.2.3.4", "example.com") is False

    def test_returns_false_on_softfail(self):
        mock_spf = MagicMock()
        mock_spf.check.return_value = ("softfail", 250, "soft fail")
        with patch.dict("sys.modules", {"spf": mock_spf}):
            assert validate_spf_live("1.2.3.4", "example.com") is False

    def test_returns_none_on_neutral(self):
        mock_spf = MagicMock()
        mock_spf.check.return_value = ("neutral", 250, "neutral")
        with patch.dict("sys.modules", {"spf": mock_spf}):
            assert validate_spf_live("1.2.3.4", "example.com") is None

    def test_returns_none_on_none_result(self):
        mock_spf = MagicMock()
        mock_spf.check.return_value = ("none", 250, "no SPF record")
        with patch.dict("sys.modules", {"spf": mock_spf}):
            assert validate_spf_live("1.2.3.4", "example.com") is None

    def test_returns_none_on_exception(self):
        mock_spf = MagicMock()
        mock_spf.check.side_effect = Exception("DNS timeout")
        with patch.dict("sys.modules", {"spf": mock_spf}):
            assert validate_spf_live("1.2.3.4", "example.com") is None


class TestSpfLiveIntegration:
    """Test that live SPF overrides header parsing in analyze_headers."""

    @patch("app.services.header_analysis.header_analyzer.validate_spf_live")
    def test_live_spf_pass_overrides_header_fail(self, mock_validate):
        """Header says spf=fail but live DNS says pass — live wins."""
        mock_validate.return_value = True
        headers = {
            "Authentication-Results": "mx.evil.com; spf=fail; dkim=pass; dmarc=pass",
        }
        result = analyze_headers(
            headers=headers,
            sender="legit@example.com",
            reply_to="legit@example.com",
            return_path="<legit@example.com>",
            originating_ip="93.184.216.34",
        )
        assert result.spf_pass is True
        assert result.spf_fail is False
        assert result.authentication_results["spf_source"] == "live_dns"

    @patch("app.services.header_analysis.header_analyzer.validate_spf_live")
    def test_live_spf_fail_overrides_header_pass(self, mock_validate):
        """Header says spf=pass (forged) but live DNS says fail — live wins."""
        mock_validate.return_value = False
        headers = {
            "Authentication-Results": "mx.google.com; spf=pass; dkim=pass; dmarc=pass",
        }
        result = analyze_headers(
            headers=headers,
            sender="attacker@evil.com",
            reply_to="attacker@evil.com",
            return_path="<attacker@evil.com>",
            originating_ip="185.100.87.42",
        )
        assert result.spf_pass is False
        assert result.spf_fail is True
        assert result.authentication_results["spf_source"] == "live_dns"

    @patch("app.services.header_analysis.header_analyzer.validate_spf_live")
    def test_falls_back_to_header_when_live_returns_none(self, mock_validate):
        """Live validation inconclusive — falls back to header parsing."""
        mock_validate.return_value = None
        headers = {
            "Authentication-Results": "mx.example.com; spf=pass; dkim=pass; dmarc=pass",
        }
        result = analyze_headers(
            headers=headers,
            sender="user@example.com",
            reply_to="user@example.com",
            return_path="<user@example.com>",
            originating_ip="1.2.3.4",
        )
        assert result.spf_pass is True
        assert result.authentication_results["spf_source"] == "header"


class TestReceivedHeadersCounting:
    """Test SMTP hop counting with the received_headers list."""

    def test_counts_multiple_received_headers(self):
        result = analyze_headers(
            headers={},
            sender="x@y.com",
            reply_to=None,
            return_path=None,
            received_headers=[
                "from mail1.example.com by mx.example.com",
                "from mail2.relay.com by mail1.example.com",
                "from [185.100.87.42] by mail2.relay.com",
            ],
        )
        assert result.num_received_headers == 3
        assert result.smtp_hops == 3

    def test_single_received_header(self):
        result = analyze_headers(
            headers={},
            sender="x@y.com",
            reply_to=None,
            return_path=None,
            received_headers=["from [1.2.3.4] by mx.example.com"],
        )
        assert result.num_received_headers == 1
        assert result.smtp_hops == 1

    def test_empty_received_headers(self):
        result = analyze_headers(
            headers={},
            sender="x@y.com",
            reply_to=None,
            return_path=None,
            received_headers=[],
        )
        assert result.num_received_headers == 0
        assert result.smtp_hops == 0

    def test_falls_back_to_dict_when_received_headers_not_provided(self):
        """Legacy path: received_headers=None uses dict iteration."""
        headers = {"Received": "from [1.2.3.4] by mx.example.com"}
        result = analyze_headers(
            headers=headers,
            sender="x@y.com",
            reply_to=None,
            return_path=None,
        )
        # Dict can only hold one Received key, so count is 1
        assert result.num_received_headers == 1
        assert result.smtp_hops == 1


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
