"""
PhisMail — ML Classifier
Wraps the rule-based scorer with ML-compatible interface for future model integration.
"""

from typing import Dict, Optional, List
import json
import os

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()


class PhishingClassifier:
    """ML-compatible classifier interface.

    Currently wraps the rule-based scorer.
    Designed to be swapped with a trained model (RandomForest/XGBoost).
    """

    def __init__(self, model_path: Optional[str] = None):
        self.model = None
        self.model_name = "rule_based_v1"
        self.model_version = "1.0.0"
        self._load_model(model_path)

    def _load_model(self, model_path: Optional[str] = None):
        """Load a trained model if available, otherwise use rule-based."""

        path = model_path or os.path.join(settings.ml_model_path, "phishing_model.pkl")

        if os.path.exists(path):
            try:
                import joblib
                self.model = joblib.load(path)
                self.model_name = "trained_model"
                logger.info("ml_model_loaded", path=path)
            except Exception as e:
                logger.warning("ml_model_load_failed", error=str(e))
                self.model = None
        else:
            logger.info("using_rule_based_scorer", reason="no trained model found")

    def predict(self, features: Dict[str, float]) -> Dict:
        """Predict phishing probability."""

        if self.model is not None:
            return self._predict_with_model(features)
        else:
            return self._predict_rule_based(features)

    def _predict_with_model(self, features: Dict[str, float]) -> Dict:
        """Use trained ML model for prediction."""

        import numpy as np

        # Convert feature dict to array in consistent order
        feature_names = sorted(features.keys())
        feature_array = np.array([[features.get(f, 0.0) for f in feature_names]])

        try:
            probability = self.model.predict_proba(feature_array)[0][1]
            prediction = self.model.predict(feature_array)[0]

            return {
                "phishing_probability": float(probability),
                "prediction": int(prediction),
                "model_name": self.model_name,
                "model_version": self.model_version,
            }
        except Exception as e:
            logger.error("ml_prediction_failed", error=str(e))
            return self._predict_rule_based(features)

    def _predict_rule_based(self, features: Dict[str, float]) -> Dict:
        """Fallback rule-based prediction."""

        from app.services.risk_scoring.rule_engine import calculate_risk_score

        result = calculate_risk_score(features)

        return {
            "phishing_probability": result.risk_score / 100.0,
            "prediction": 1 if result.verdict == "PHISHING" else 0,
            "model_name": "rule_based",
            "model_version": "1.0.0",
        }
