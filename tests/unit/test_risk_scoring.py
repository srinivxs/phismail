"""
PhisMail — Risk Scoring Engine Tests
"""

import pytest
from app.services.risk_scoring.rule_engine import (
    calculate_risk_score,
    RiskScoringResult,
    FEATURE_WEIGHTS,
    SEVERITY_MAP,
)


class TestCalculateRiskScore:
    """Test weighted risk scoring and verdict logic."""

    def test_phishing_verdict_high_risk(self):
        """Features that unambiguously indicate phishing should produce PHISHING verdict."""
        features = {
            "openphish_match": 1.0,
            "phishtank_match": 1.0,
            "reply_to_mismatch": 1.0,
            "domain_recent_registration": 1.0,
        }
        result = calculate_risk_score(features)
        assert result.verdict == "PHISHING"
        assert result.risk_score >= 70

    def test_safe_verdict_low_risk(self):
        """Legitimate email features should produce SAFE verdict."""
        features = {
            "spf_pass": 1.0,
            "dkim_pass": 1.0,
            "dmarc_pass": 1.0,
        }
        result = calculate_risk_score(features)
        assert result.verdict == "SAFE"
        assert result.risk_score < 40

    def test_suspicious_verdict_moderate_risk(self):
        """Mixed signals should produce SUSPICIOUS verdict."""
        features = {
            "reply_to_mismatch": 1.0,            # +15
            "urgency_keyword_count": 3.0,         # +9
            "url_shortened": 1.0,                 # +8
            "credential_request_keywords": 2.0,   # +10
            "domain_recent_registration": 1.0,    # +20
            "spf_pass": 1.0,                      # -5
        }
        result = calculate_risk_score(features)
        assert result.verdict in ("SUSPICIOUS", "PHISHING")
        assert result.risk_score >= 40

    def test_risk_score_clamped_0_to_100(self):
        """Score should never exceed [0, 100] range."""
        extreme_features = {k: 100.0 for k in FEATURE_WEIGHTS if FEATURE_WEIGHTS[k] > 0}
        result = calculate_risk_score(extreme_features)
        assert result.risk_score <= 100.0

        safe_features = {k: 100.0 for k in FEATURE_WEIGHTS if FEATURE_WEIGHTS[k] < 0}
        result = calculate_risk_score(safe_features)
        assert result.risk_score >= 0.0

    def test_empty_features_safe(self):
        """Empty features should produce SAFE verdict."""
        result = calculate_risk_score({})
        assert result.verdict == "SAFE"
        assert result.risk_score == 0.0

    def test_indicators_sorted_by_severity(self):
        """Indicators should be sorted CRITICAL → HIGH → MEDIUM → LOW."""
        features = {
            "openphish_match": 1.0,      # CRITICAL
            "reply_to_mismatch": 1.0,    # HIGH
            "url_shortened": 1.0,        # MEDIUM
            "urgency_keyword_count": 2.0, # LOW
        }
        result = calculate_risk_score(features)
        severities = [ind["severity"] for ind in result.indicators]
        # CRITICAL should come first
        if "CRITICAL" in severities and "LOW" in severities:
            assert severities.index("CRITICAL") < severities.index("LOW")

    def test_top_contributors_limited_to_10(self):
        """Top contributors should be capped at 10."""
        features = {k: 1.0 for k in list(FEATURE_WEIGHTS.keys())[:15]}
        result = calculate_risk_score(features)
        assert len(result.top_contributors) <= 10

    def test_top_contributors_sorted_by_magnitude(self):
        """Top contributors sorted by absolute attribution score."""
        features = {
            "openphish_match": 1.0,
            "mixed_case_domain": 1.0,
        }
        result = calculate_risk_score(features)
        scores = [abs(tc["attribution_score"]) for tc in result.top_contributors]
        assert scores == sorted(scores, reverse=True)

    def test_negative_weight_features_reduce_score(self):
        """SPF/DKIM/DMARC pass should reduce risk score."""
        baseline = calculate_risk_score({"reply_to_mismatch": 1.0})
        with_auth = calculate_risk_score({"reply_to_mismatch": 1.0, "spf_pass": 1.0})
        assert with_auth.risk_score < baseline.risk_score

    def test_indicators_only_positive_contributors(self):
        """Indicators list should only contain positive contributionscontribuutors."""
        features = {"spf_pass": 1.0, "openphish_match": 1.0}
        result = calculate_risk_score(features)
        for ind in result.indicators:
            assert ind["indicator_type"] != "spf_pass"  # Negative weight, should not appear


class TestFeatureWeightsConsistency:
    """Test that feature weights and severity maps are consistent."""

    def test_all_severity_mapped_features_have_weights(self):
        """Every feature in SEVERITY_MAP should have a weight."""
        for feature in SEVERITY_MAP:
            assert feature in FEATURE_WEIGHTS, f"{feature} in SEVERITY_MAP but not in FEATURE_WEIGHTS"

    def test_critical_features_have_high_weight(self):
        """CRITICAL severity features should have weight >= 25."""
        for feature, severity in SEVERITY_MAP.items():
            if severity == "CRITICAL":
                assert FEATURE_WEIGHTS[feature] >= 25.0, f"{feature} is CRITICAL but weight is {FEATURE_WEIGHTS[feature]}"
