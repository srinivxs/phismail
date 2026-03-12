"""
PhisMail — Security Module Tests
"""

import pytest
from app.core.security import (
    compute_sha256,
    compute_url_hash,
    BRAND_KEYWORDS,
    SUSPICIOUS_TLDS,
    EXECUTABLE_EXTENSIONS,
    URL_SHORTENERS,
)


class TestComputeSha256:
    """Test SHA256 hashing utility."""

    def test_deterministic(self):
        data = b"hello world"
        assert compute_sha256(data) == compute_sha256(data)

    def test_different_data_different_hash(self):
        assert compute_sha256(b"hello") != compute_sha256(b"world")

    def test_returns_hex_string(self):
        result = compute_sha256(b"test")
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_empty_bytes(self):
        result = compute_sha256(b"")
        assert len(result) == 64


class TestComputeUrlHash:
    """Test URL hash normalization."""

    def test_deterministic(self):
        assert compute_url_hash("https://example.com") == compute_url_hash("https://example.com")

    def test_case_insensitive(self):
        assert compute_url_hash("https://Example.COM") == compute_url_hash("https://example.com")

    def test_strips_trailing_slash(self):
        assert compute_url_hash("https://example.com/") == compute_url_hash("https://example.com")

    def test_strips_whitespace(self):
        assert compute_url_hash("  https://example.com  ") == compute_url_hash("https://example.com")


class TestSecurityConstants:
    """Verify security constant lists are populated and reasonable."""

    def test_brand_keywords_populated(self):
        assert len(BRAND_KEYWORDS) >= 20
        assert "paypal" in BRAND_KEYWORDS
        assert "microsoft" in BRAND_KEYWORDS

    def test_suspicious_tlds_populated(self):
        assert len(SUSPICIOUS_TLDS) >= 10
        assert ".tk" in SUSPICIOUS_TLDS

    def test_executable_extensions_populated(self):
        assert ".exe" in EXECUTABLE_EXTENSIONS
        assert ".bat" in EXECUTABLE_EXTENSIONS

    def test_url_shorteners_populated(self):
        assert "bit.ly" in URL_SHORTENERS
        assert "t.co" in URL_SHORTENERS
