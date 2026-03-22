"""Tests for the ML ensemble classifier and feature extractor."""

import pytest
import numpy as np
from unittest.mock import patch, MagicMock

from app.ml.feature_extractor import EmailFeatureExtractor
from app.ml.ensemble_classifier import EnsemblePhishingClassifier


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def extractor():
    return EmailFeatureExtractor()


@pytest.fixture
def legitimate_email():
    return {
        "from": "The Souled Store <connect@hello.thesouledstore.com>",
        "return_path": "campaign@ncdelivery.hello.thesouledstore.com",
        "reply_to": "The Souled Store <connect@hello.thesouledstore.com>",
        "subject": "Fresh Fits Alert: New Collection",
        "body_text": "Check out our new collection of pants...",
        "body_html": "<html><body>Check out...</body></html>",
        "authentication_results": "spf=pass dkim=pass dmarc=pass",
        "urls": [
            "https://www.thesouledstore.com/men/pants",
            "https://elink.hello.thesouledstore.com/track?id=123",
        ],
        "received_headers": ["hop1", "hop2"],
        "message_id": "<msg123@thesouledstore.com>",
        "list_unsubscribe": "mailto:unsubscribe@thesouledstore.com",
        "attachments": [],
    }


@pytest.fixture
def phishing_email():
    return {
        "from": "PayPal Security <security@paypa1-verify.tk>",
        "return_path": "bounce@spam-server.xyz",
        "reply_to": "phisher@malicious.com",
        "subject": "URGENT: Verify your account immediately!",
        "body_text": "Click here now: http://paypal.com.verify.tk/urgent",
        "body_html": "<html><body>Click here!</body></html>",
        "authentication_results": "spf=fail dkim=fail dmarc=fail",
        "urls": [
            "http://paypal.com.verify.tk/urgent",
            "http://192.168.1.100/login",
        ],
        "received_headers": ["hop1"],
        "message_id": "",
        "list_unsubscribe": "",
        "attachments": ["invoice.exe"],
    }


# =============================================================================
# Feature Extractor Tests
# =============================================================================

class TestFeatureExtractor:

    def test_extracts_35_plus_features(self, extractor, legitimate_email):
        features = extractor.extract_all_features(legitimate_email)
        assert len(features) >= 35

    def test_auth_features_all_pass(self, extractor, legitimate_email):
        features = extractor.extract_all_features(legitimate_email)
        assert features["spf_pass"] == 1
        assert features["dkim_pass"] == 1
        assert features["dmarc_pass"] == 1
        assert features["all_auth_pass"] == 1
        assert features["auth_score"] == 3

    def test_auth_features_all_fail(self, extractor, phishing_email):
        features = extractor.extract_all_features(phishing_email)
        assert features["spf_pass"] == 0
        assert features["dkim_pass"] == 0
        assert features["dmarc_pass"] == 0
        assert features["all_auth_pass"] == 0
        assert features["auth_score"] == 0

    def test_detects_suspicious_tld(self, extractor, phishing_email):
        features = extractor.extract_all_features(phishing_email)
        assert features["has_suspicious_tld"] == 1

    def test_legitimate_tld_not_flagged(self, extractor, legitimate_email):
        features = extractor.extract_all_features(legitimate_email)
        assert features["has_suspicious_tld"] == 0

    def test_detects_ip_in_url(self, extractor, phishing_email):
        features = extractor.extract_all_features(phishing_email)
        assert features["has_ip_in_url"] == 1

    def test_no_ip_in_legitimate_url(self, extractor, legitimate_email):
        features = extractor.extract_all_features(legitimate_email)
        assert features["has_ip_in_url"] == 0

    def test_detects_unsubscribe_header(self, extractor, legitimate_email):
        features = extractor.extract_all_features(legitimate_email)
        assert features["has_unsubscribe"] == 1

    def test_no_unsubscribe_phishing(self, extractor, phishing_email):
        features = extractor.extract_all_features(phishing_email)
        assert features["has_unsubscribe"] == 0

    def test_reply_to_mismatch(self, extractor, phishing_email):
        features = extractor.extract_all_features(phishing_email)
        assert features["reply_to_mismatch"] == 1

    def test_reply_to_match(self, extractor, legitimate_email):
        features = extractor.extract_all_features(legitimate_email)
        assert features["reply_to_mismatch"] == 0

    def test_detects_attachments(self, extractor, phishing_email):
        features = extractor.extract_all_features(phishing_email)
        assert features["has_attachments"] == 1

    def test_urgency_keywords_detected(self, extractor, phishing_email):
        features = extractor.extract_all_features(phishing_email)
        assert features["high_urgency_count"] > 0

    def test_https_count(self, extractor, legitimate_email):
        features = extractor.extract_all_features(legitimate_email)
        assert features["https_count"] == 2
        assert features["http_count"] == 0

    def test_http_ratio_phishing(self, extractor, phishing_email):
        features = extractor.extract_all_features(phishing_email)
        assert features["http_ratio"] == 1.0

    def test_empty_urls(self, extractor):
        email = {"from": "test@test.com", "subject": "test", "body_text": "test"}
        features = extractor.extract_all_features(email)
        assert features["total_urls"] == 0
        assert features["has_url_shortener"] == 0

    def test_esp_detection(self, extractor, legitimate_email):
        features = extractor.extract_all_features(legitimate_email)
        assert features["is_known_esp"] == 1

    def test_update_known_brands(self, extractor):
        extractor.update_known_brands(["newbrand.com"])
        assert "newbrand.com" in extractor.known_brands


# =============================================================================
# Ensemble Classifier Tests
# =============================================================================

class TestEnsembleClassifier:

    def test_untrained_raises(self):
        classifier = EnsemblePhishingClassifier()
        with pytest.raises(ValueError, match="not trained"):
            classifier.predict({"feature_1": 0.5})

    def test_train_and_predict(self):
        classifier = EnsemblePhishingClassifier()
        np.random.seed(42)

        n_samples = 100
        n_features = 10
        X = np.random.rand(n_samples, n_features)
        y = np.random.randint(0, 2, n_samples)
        feature_names = [f"feat_{i}" for i in range(n_features)]

        metrics = classifier.train(X, y, feature_names=feature_names, use_smote=False)

        assert classifier.is_trained
        assert "ensemble_metrics" in metrics
        assert metrics["ensemble_metrics"]["accuracy"] >= 0

    def test_whitelist_returns_safe(self):
        classifier = EnsemblePhishingClassifier()
        classifier.is_trained = True
        classifier.feature_names = ["feat_1"]
        classifier.add_to_whitelist("safe-domain.com")

        result = classifier.predict({"feat_1": 1.0, "_from_domain": "safe-domain.com"})
        assert result["prediction"] == "SAFE"
        assert result["stage"] == "whitelist"

    def test_blacklist_returns_phishing(self):
        classifier = EnsemblePhishingClassifier()
        classifier.is_trained = True
        classifier.feature_names = ["feat_1"]
        classifier.add_to_blacklist("evil.tk")

        result = classifier.predict({"feat_1": 1.0, "_from_domain": "evil.tk"})
        assert result["prediction"] == "PHISHING"
        assert result["stage"] == "blacklist"

    def test_auth_rules_safe(self):
        classifier = EnsemblePhishingClassifier()
        classifier.is_trained = True
        classifier.feature_names = ["all_auth_pass", "is_known_esp"]

        features = {
            "all_auth_pass": 1,
            "is_known_esp": 1,
            "esp_aligned": 0,
            "domain_exact_match": 0,
            "base_domain_match": 0,
            "is_known_brand": 0,
            "_from_domain": "test.com",
        }
        result = classifier.predict(features)
        assert result["prediction"] == "SAFE"
        assert result["stage"] == "auth_rules"

    def test_feature_importance(self):
        classifier = EnsemblePhishingClassifier()
        classifier.feature_importances = {"a": 0.5, "b": 0.3, "c": 0.2}
        top = classifier.get_feature_importance(top_n=2)
        assert list(top.keys()) == ["a", "b"]

    def test_save_and_load(self, tmp_path):
        classifier = EnsemblePhishingClassifier(model_version="test_v1")
        np.random.seed(42)
        X = np.random.rand(50, 5)
        y = np.random.randint(0, 2, 50)
        classifier.train(X, y, feature_names=[f"f{i}" for i in range(5)], use_smote=False)

        model_path = str(tmp_path / "test_model.pkl")
        classifier.save_model(model_path)

        new_classifier = EnsemblePhishingClassifier()
        new_classifier.load_model(model_path)

        assert new_classifier.is_trained
        assert new_classifier.model_version == "test_v1"
        assert len(new_classifier.feature_names) == 5

    def test_calibration_reduces_phishing_prob(self):
        classifier = EnsemblePhishingClassifier()
        prob, _ = classifier._calibrate_confidence(0.8, {"auth_score": 3})
        assert prob < 0.8  # Should be reduced (0.8 * 0.7 = 0.56)

    def test_no_calibration_low_auth(self):
        classifier = EnsemblePhishingClassifier()
        prob, _ = classifier._calibrate_confidence(0.8, {"auth_score": 1})
        assert prob == 0.8  # No reduction when auth_score < 2
