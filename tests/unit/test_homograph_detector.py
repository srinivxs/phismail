"""
PhisMail — Homograph Detector Tests
"""

import pytest
from app.services.domain_intelligence.homograph_detector import (
    detect_homograph,
    _normalize_confusables,
    _calculate_similarity,
)


class TestDetectHomograph:
    """Test Unicode homograph and typosquatting detection."""

    def test_detects_cyrillic_homograph(self):
        # "раypal.com" — Cyrillic 'р' and 'а' look like Latin 'p' and 'a'
        result = detect_homograph("раypal.com")
        assert result.is_homograph is True
        assert len(result.confusable_chars) > 0

    def test_detects_idn_domain(self):
        # Domain with non-ASCII characters
        result = detect_homograph("éxample.com")
        assert result.is_idn is True

    def test_clean_domain_no_homograph(self):
        result = detect_homograph("legitimate-business.com")
        assert result.is_homograph is False
        assert len(result.confusable_chars) == 0

    def test_typosquatting_detection(self):
        # "paypa1" is similar to "paypal"
        result = detect_homograph("paypa1.com")
        assert result.similarity_score > 0.7

    def test_brand_matching_on_normalized(self):
        # "gogle" is a typosquat of "google" (one letter missing)
        result = detect_homograph("gogle.com")
        assert result.similarity_score > 0


class TestNormalizeConfusables:
    """Test confusable character normalization."""

    def test_cyrillic_to_latin(self):
        # Cyrillic 'а' → Latin 'a', Cyrillic 'о' → Latin 'o'
        assert _normalize_confusables("аo") == "ao"

    def test_no_change_ascii(self):
        assert _normalize_confusables("hello") == "hello"

    def test_empty(self):
        assert _normalize_confusables("") == ""


class TestCalculateSimilarity:
    """Test Levenshtein similarity."""

    def test_identical_strings(self):
        assert _calculate_similarity("paypal", "paypal") == 1.0

    def test_empty_strings(self):
        assert _calculate_similarity("", "") == 0.0

    def test_one_char_diff(self):
        sim = _calculate_similarity("paypal", "paypa1")
        assert sim > 0.8

    def test_completely_different(self):
        sim = _calculate_similarity("abcdef", "zyxwvu")
        assert sim < 0.3

    def test_typosquatting_distance(self):
        # "microsft" vs "microsoft" — one char missing
        sim = _calculate_similarity("microsft", "microsoft")
        assert sim > 0.85
