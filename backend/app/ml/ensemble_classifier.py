"""
PhisMail — Ensemble Phishing Classifier
Combines Random Forest + Gradient Boosting with authentication hard rules.
Optimized for LOW FALSE POSITIVES.
"""

import numpy as np
import joblib
from typing import Dict, Tuple, Any, Optional, List
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score,
)

from app.core.logging import get_logger

logger = get_logger(__name__)


class EnsemblePhishingClassifier:
    """Hybrid ensemble classifier combining:

    1. Whitelist/blacklist domain checks
    2. Hard authentication rules (auto-pass/fail)
    3. Random Forest (primary model, 60% weight)
    4. Gradient Boosting (secondary model, 40% weight)
    5. Confidence calibration based on auth context

    Designed to minimize false positives in production.
    """

    def __init__(self, model_version: str = "v1.0") -> None:
        self.model_version = model_version

        self.rf_model = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            max_features="sqrt",
            class_weight={0: 1, 1: 1.5},
            random_state=42,
            n_jobs=-1,
        )

        self.gb_model = GradientBoostingClassifier(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=5,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
        )

        self.scaler = StandardScaler()
        self.feature_names: List[str] = []
        self.feature_importances: Dict[str, float] = {}
        self.is_trained = False

        self.HIGH_CONFIDENCE_THRESHOLD = 0.85
        self.LOW_CONFIDENCE_THRESHOLD = 0.25

        self.whitelisted_domains: set = set()
        self.blacklisted_domains: set = set()

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train(
        self,
        X: np.ndarray,
        y: np.ndarray,
        feature_names: Optional[List[str]] = None,
        use_smote: bool = True,
        test_size: float = 0.2,
    ) -> Dict[str, Any]:
        """Train both models in the ensemble.

        Args:
            X: Feature matrix (n_samples, n_features).
            y: Labels (0 = legitimate, 1 = phishing).
            feature_names: Ordered list of feature names.
            use_smote: Balance dataset with SMOTE if True.
            test_size: Fraction of data for testing.

        Returns:
            Dict with rf_metrics, gb_metrics, ensemble_metrics, cv scores.
        """
        logger.info("ensemble_training_started", n_samples=len(X))

        if feature_names:
            self.feature_names = feature_names

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42,
            stratify=y if len(set(y)) > 1 else None,
        )

        if use_smote and len(set(y_train)) > 1:
            try:
                from imblearn.over_sampling import SMOTE
                smote = SMOTE(random_state=42)
                X_train, y_train = smote.fit_resample(X_train, y_train)
                logger.info("smote_applied", n_resampled=len(X_train))
            except ImportError:
                logger.warning("smote_not_available")

        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        # Train Random Forest
        self.rf_model.fit(X_train_scaled, y_train)
        rf_pred = self.rf_model.predict(X_test_scaled)
        rf_proba = self.rf_model.predict_proba(X_test_scaled)[:, 1]

        # Train Gradient Boosting
        self.gb_model.fit(X_train_scaled, y_train)
        gb_pred = self.gb_model.predict(X_test_scaled)
        gb_proba = self.gb_model.predict_proba(X_test_scaled)[:, 1]

        # Ensemble predictions
        ensemble_proba = (rf_proba + gb_proba) / 2
        ensemble_pred = (ensemble_proba > 0.5).astype(int)

        metrics = {
            "rf_metrics": self._calculate_metrics(y_test, rf_pred, rf_proba),
            "gb_metrics": self._calculate_metrics(y_test, gb_pred, gb_proba),
            "ensemble_metrics": self._calculate_metrics(y_test, ensemble_pred, ensemble_proba),
        }

        if self.feature_names:
            self.feature_importances = dict(zip(
                self.feature_names, self.rf_model.feature_importances_,
            ))

        cv_scores = cross_val_score(
            self.rf_model, X_train_scaled, y_train, cv=5, scoring="roc_auc",
        )
        metrics["cv_mean_auc"] = float(cv_scores.mean())
        metrics["cv_std_auc"] = float(cv_scores.std())

        self.is_trained = True
        logger.info(
            "ensemble_training_complete",
            accuracy=metrics["ensemble_metrics"]["accuracy"],
            fpr=metrics["ensemble_metrics"]["false_positive_rate"],
        )
        return metrics

    # ------------------------------------------------------------------
    # Prediction
    # ------------------------------------------------------------------

    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Multi-stage prediction: whitelist → blacklist → auth rules → ML.

        Args:
            features: Dict of extracted features from EmailFeatureExtractor.

        Returns:
            Prediction result with confidence and reasoning.
        """
        if not self.is_trained:
            raise ValueError("Model not trained. Call train() or load_model() first.")

        # Stage 1: Whitelist
        from_domain = features.get("_from_domain", "")
        if from_domain in self.whitelisted_domains:
            return self._make_result(
                "SAFE", 1.0, 0.0, 1.0,
                f"Domain {from_domain} is whitelisted", "whitelist",
            )

        # Stage 2: Blacklist
        if from_domain in self.blacklisted_domains:
            return self._make_result(
                "PHISHING", 1.0, 1.0, 0.0,
                f"Domain {from_domain} is blacklisted", "blacklist",
            )

        # Stage 3: Authentication hard rules
        auth_result = self._check_authentication_rules(features)
        if auth_result:
            return auth_result

        # Stage 4: ML ensemble
        return self._ml_predict(features)

    def _check_authentication_rules(self, features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Hard rules based on email authentication.

        Returns None if no rule matches (continues to ML stage).
        """
        all_auth = features.get("all_auth_pass", 0) == 1
        is_esp = features.get("is_known_esp", 0) == 1
        esp_aligned = features.get("esp_aligned", 0) == 1
        domain_exact = features.get("domain_exact_match", 0) == 1
        base_match = features.get("base_domain_match", 0) == 1
        is_brand = features.get("is_known_brand", 0) == 1

        if all_auth and (is_esp or esp_aligned or base_match):
            return self._make_result(
                "SAFE", 0.95, 0.05, 0.95,
                "All authentication passed with legitimate ESP", "auth_rules",
            )

        if all_auth and domain_exact:
            return self._make_result(
                "SAFE", 0.98, 0.02, 0.98,
                "All authentication passed, exact domain match", "auth_rules",
            )

        if is_brand and all_auth:
            return self._make_result(
                "SAFE", 0.97, 0.03, 0.97,
                "Known brand with all authentication passed", "auth_rules",
            )

        return None

    def _ml_predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """ML-based prediction using the weighted ensemble."""
        X = self._features_to_array(features)
        X_scaled = self.scaler.transform(X.reshape(1, -1))

        rf_proba = self.rf_model.predict_proba(X_scaled)[0]
        gb_proba = self.gb_model.predict_proba(X_scaled)[0]

        # Weighted ensemble: RF 60%, GB 40%
        ensemble_proba = rf_proba * 0.6 + gb_proba * 0.4
        phishing_prob = float(ensemble_proba[1])

        # Calibrate based on auth context
        phishing_prob, confidence = self._calibrate_confidence(phishing_prob, features)

        if phishing_prob > self.HIGH_CONFIDENCE_THRESHOLD:
            prediction = "PHISHING"
            reasoning = f"High phishing probability ({phishing_prob:.0%})"
        elif phishing_prob < self.LOW_CONFIDENCE_THRESHOLD:
            prediction = "SAFE"
            reasoning = f"Low phishing probability ({phishing_prob:.0%})"
        else:
            prediction = "SUSPICIOUS"
            reasoning = f"Medium confidence ({phishing_prob:.0%}) — manual review recommended"

        result = self._make_result(
            prediction, confidence, phishing_prob, 1 - phishing_prob,
            reasoning, "ml_ensemble",
        )
        result["rf_probability"] = float(rf_proba[1])
        result["gb_probability"] = float(gb_proba[1])
        return result

    def _calibrate_confidence(
        self, phishing_prob: float, features: Dict[str, Any],
    ) -> Tuple[float, float]:
        """Reduce phishing probability when authentication is strong."""
        auth_score = features.get("auth_score", 0)

        if auth_score >= 2:
            phishing_prob *= 0.7
            confidence = min(0.95, (1 - abs(phishing_prob - 0.5)) * 2)
        else:
            confidence = (1 - abs(phishing_prob - 0.5)) * 2

        return phishing_prob, float(confidence)

    # ------------------------------------------------------------------
    # Whitelist / Blacklist
    # ------------------------------------------------------------------

    def add_to_whitelist(self, domain: str) -> None:
        self.whitelisted_domains.add(domain.lower())

    def add_to_blacklist(self, domain: str) -> None:
        self.blacklisted_domains.add(domain.lower())

    def load_whitelist(self, domains: List[str]) -> None:
        self.whitelisted_domains = set(d.lower() for d in domains)

    def load_blacklist(self, domains: List[str]) -> None:
        self.blacklisted_domains = set(d.lower() for d in domains)

    # ------------------------------------------------------------------
    # Feature importance
    # ------------------------------------------------------------------

    def get_feature_importance(self, top_n: int = 10) -> Dict[str, float]:
        if not self.feature_importances:
            return {}
        sorted_features = sorted(
            self.feature_importances.items(), key=lambda x: x[1], reverse=True,
        )
        return dict(sorted_features[:top_n])

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save_model(self, filepath: str) -> None:
        if not self.is_trained:
            raise ValueError("Cannot save untrained model")

        model_data = {
            "rf_model": self.rf_model,
            "gb_model": self.gb_model,
            "scaler": self.scaler,
            "feature_names": self.feature_names,
            "feature_importances": self.feature_importances,
            "model_version": self.model_version,
            "high_threshold": self.HIGH_CONFIDENCE_THRESHOLD,
            "low_threshold": self.LOW_CONFIDENCE_THRESHOLD,
        }
        joblib.dump(model_data, filepath)
        logger.info("ensemble_model_saved", path=filepath)

    def load_model(self, filepath: str) -> None:
        model_data = joblib.load(filepath)

        self.rf_model = model_data["rf_model"]
        self.gb_model = model_data["gb_model"]
        self.scaler = model_data["scaler"]
        self.feature_names = model_data["feature_names"]
        self.feature_importances = model_data.get("feature_importances", {})
        self.model_version = model_data.get("model_version", "unknown")
        self.HIGH_CONFIDENCE_THRESHOLD = model_data.get("high_threshold", 0.85)
        self.LOW_CONFIDENCE_THRESHOLD = model_data.get("low_threshold", 0.25)

        self.is_trained = True
        logger.info("ensemble_model_loaded", path=filepath, version=self.model_version)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _features_to_array(self, features: Dict[str, Any]) -> np.ndarray:
        if not self.feature_names:
            raise ValueError("Feature names not set. Train model first.")
        return np.array([features.get(name, 0) for name in self.feature_names])

    def _make_result(
        self,
        prediction: str,
        confidence: float,
        phishing_prob: float,
        legit_prob: float,
        reasoning: str,
        stage: str,
    ) -> Dict[str, Any]:
        return {
            "prediction": prediction,
            "confidence": confidence,
            "phishing_probability": phishing_prob,
            "legitimate_probability": legit_prob,
            "reasoning": reasoning,
            "stage": stage,
            "model_version": self.model_version,
        }

    def _calculate_metrics(self, y_true, y_pred, y_proba) -> Dict[str, float]:
        cm = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)

        return {
            "accuracy": float(accuracy_score(y_true, y_pred)),
            "precision": float(precision_score(y_true, y_pred, zero_division=0)),
            "recall": float(recall_score(y_true, y_pred, zero_division=0)),
            "f1_score": float(f1_score(y_true, y_pred, zero_division=0)),
            "auc_roc": float(roc_auc_score(y_true, y_proba)) if len(set(y_true)) > 1 else 0.0,
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
            "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0,
        }
