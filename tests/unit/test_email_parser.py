"""
PhisMail — Email Parser Tests
"""

import pytest
from app.services.email_parser.parser import (
    parse_eml_bytes,
    extract_urls_from_content,
    ParsedEmailResult,
)


class TestParseEmlBytes:
    """Test .eml parsing into structured components."""

    def test_extracts_sender_and_reply_to(self, sample_eml_content):
        result = parse_eml_bytes(sample_eml_content)
        assert "attacker@evil.com" in result.sender
        assert "phisher@malicious.net" in result.reply_to

    def test_extracts_return_path(self, sample_eml_content):
        result = parse_eml_bytes(sample_eml_content)
        assert "different.org" in result.return_path

    def test_extracts_subject(self, sample_eml_content):
        result = parse_eml_bytes(sample_eml_content)
        assert "URGENT" in result.subject
        assert "suspended" in result.subject

    def test_extracts_headers(self, sample_eml_content):
        result = parse_eml_bytes(sample_eml_content)
        assert len(result.headers) > 0
        assert "Authentication-Results" in result.headers

    def test_extracts_originating_ip(self, sample_eml_content):
        result = parse_eml_bytes(sample_eml_content)
        assert result.originating_ip == "185.100.87.42"

    def test_extracts_body_text(self, sample_eml_content):
        result = parse_eml_bytes(sample_eml_content)
        assert result.body_text is not None
        assert "locked" in result.body_text.lower()

    def test_extracts_body_html(self, sample_eml_content):
        result = parse_eml_bytes(sample_eml_content)
        assert result.body_html is not None
        assert "<html>" in result.body_html.lower()

    def test_extracts_attachment_metadata(self, sample_eml_content):
        result = parse_eml_bytes(sample_eml_content)
        assert len(result.attachments) >= 1
        attachment = result.attachments[0]
        assert "filename" in attachment
        assert "sha256" in attachment
        assert attachment["size"] > 0

    def test_extracts_urls_from_body(self, sample_eml_content):
        result = parse_eml_bytes(sample_eml_content)
        assert len(result.urls) >= 1
        assert any("paypal-security.evil.ru" in u for u in result.urls)

    def test_skips_private_ips_for_originating(self):
        eml = b"""From: test@example.com
To: other@example.com
Received: from [192.168.1.1] by internal.corp
Received: from [10.0.0.5] by internal.corp

Just a test.
"""
        result = parse_eml_bytes(eml)
        assert result.originating_ip is None


class TestExtractUrls:
    """Test URL extraction from text and HTML."""

    def test_extracts_from_plain_text(self):
        urls = extract_urls_from_content("Visit https://example.com/page", None)
        assert len(urls) >= 1
        assert any("example.com" in u for u in urls)

    def test_extracts_from_html_href(self):
        html = '<a href="https://phish.com/login">Click</a>'
        urls = extract_urls_from_content(None, html)
        assert any("phish.com" in u for u in urls)

    def test_deduplicates_urls(self):
        text = "Visit https://dup.com and also https://dup.com again"
        urls = extract_urls_from_content(text, None)
        dup_count = sum(1 for u in urls if "dup.com" in u)
        assert dup_count == 1

    def test_handles_empty_input(self):
        urls = extract_urls_from_content(None, None)
        assert urls == []

    def test_strips_trailing_punctuation(self):
        text = "Go to https://example.com/page."
        urls = extract_urls_from_content(text, None)
        assert all(not u.endswith(".") for u in urls)
