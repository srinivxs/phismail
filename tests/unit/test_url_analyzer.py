"""
PhisMail — URL Analyzer Tests
"""

import pytest
from app.services.url_analysis.url_analyzer import analyze_url, _calculate_entropy


class TestAnalyzeUrl:
    """Test URL structural and obfuscation analysis."""

    def test_basic_analysis(self):
        result = analyze_url("https://example.com/page")
        assert result.domain == "example.com"
        assert result.has_https is True
        assert result.url_length == len("https://example.com/page")

    def test_detects_ip_url(self):
        result = analyze_url("http://192.168.1.1/phish")
        assert result.contains_ip is True

    def test_detects_at_symbol(self):
        result = analyze_url("http://user@evil.com/page")
        assert result.contains_at_symbol is True
        assert result.username_in_url is True

    def test_detects_url_shortener(self):
        result = analyze_url("https://bit.ly/abc123")
        assert result.is_shortened is True

    def test_normal_url_not_shortened(self):
        result = analyze_url("https://legitimate.com/path")
        assert result.is_shortened is False

    def test_counts_subdomains(self):
        result = analyze_url("https://sub1.sub2.sub3.example.com/page")
        assert result.num_subdomains >= 3

    def test_counts_query_parameters(self):
        result = analyze_url("https://example.com/page?a=1&b=2&c=3")
        assert result.num_query_parameters == 3

    def test_detects_percent_encoding(self):
        result = analyze_url("https://example.com/%70%68%69%73%68")
        assert result.percent_encoding_count >= 5

    def test_detects_double_slash_redirect(self):
        result = analyze_url("https://example.com//evil.com/path")
        assert result.double_slash_redirect is True

    def test_detects_long_query_string(self):
        long_query = "x" * 101
        result = analyze_url(f"https://example.com/?q={long_query}")
        assert result.long_query_string is True

    def test_entropy_calculation(self):
        result = analyze_url("https://example.com/page")
        assert result.entropy_score > 0

    def test_detects_brand_keyword(self):
        result = analyze_url("https://paypal-security.evil.com/login")
        assert result.brand_keyword_present is True
        assert result.detected_brand == "paypal"

    def test_no_brand_on_clean_url(self):
        result = analyze_url("https://clean-website.org/page")
        assert result.brand_keyword_present is False

    def test_http_not_https(self):
        result = analyze_url("http://insecure.com/page")
        assert result.has_https is False


class TestCalculateEntropy:
    """Test Shannon entropy computation."""

    def test_zero_entropy_empty(self):
        assert _calculate_entropy("") == 0.0

    def test_zero_entropy_single_char(self):
        assert _calculate_entropy("aaaa") == 0.0

    def test_max_entropy_balanced(self):
        # Higher entropy = more randomness
        assert _calculate_entropy("abcdef") > _calculate_entropy("aaaaaa")

    def test_high_entropy_random(self):
        assert _calculate_entropy("8f3Kz!p2Qw@9xL") > 3.0
