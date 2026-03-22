"""
PhisMail — ML Integration
Integrates the ensemble classifier into the existing analysis pipeline.
Provides prediction, feedback, and auto-whitelisting capabilities.
"""

import re
from pathlib import Path
from typing import Dict, Any, Optional

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.database import SessionLocal
from app.models.models import (
    MLPrediction, MLFeedback, DomainWhitelist, DomainBlacklist, ParsedEmail,
)
from app.ml.feature_extractor import EmailFeatureExtractor
from app.ml.ensemble_classifier import EnsemblePhishingClassifier

logger = get_logger(__name__)
settings = get_settings()


class MLIntegration:
    """Handles ML integration with PhisMail's forensic pipeline.

    Singleton — initialized once at app startup. Loads the trained ensemble
    model and domain whitelist/blacklist from the database.
    """

    _instance: Optional["MLIntegration"] = None

    def __new__(cls) -> "MLIntegration":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return

        logger.info("ml_integration_init")
        self.feature_extractor = EmailFeatureExtractor()
        self.classifier = EnsemblePhishingClassifier()

        # Try to load a pre-trained ensemble model
        model_path = Path(settings.ml_model_path) / "ensemble_model_v1.pkl"
        if model_path.exists():
            try:
                self.classifier.load_model(str(model_path))
                logger.info("ml_ensemble_model_loaded", path=str(model_path))
            except Exception as exc:
                logger.warning("ml_ensemble_model_load_failed", error=str(exc))
        else:
            logger.info("ml_no_ensemble_model", path=str(model_path))

        self._load_lists_from_db()
        self._initialized = True

    # ------------------------------------------------------------------
    # Domain lists
    # ------------------------------------------------------------------

    def _load_lists_from_db(self) -> None:
        """Load whitelists and blacklists from the database."""
        db = SessionLocal()
        try:
            whitelisted = db.query(DomainWhitelist).all()
            whitelist_domains = [w.domain for w in whitelisted]
            self.classifier.load_whitelist(whitelist_domains)
            self.feature_extractor.update_known_brands(whitelist_domains)

            blacklisted = db.query(DomainBlacklist).all()
            blacklist_domains = [b.domain for b in blacklisted]
            self.classifier.load_blacklist(blacklist_domains)

            logger.info(
                "domain_lists_loaded",
                whitelisted=len(whitelist_domains),
                blacklisted=len(blacklist_domains),
            )
        except Exception as exc:
            logger.warning("domain_lists_load_failed", error=str(exc))
        finally:
            db.close()

    # ------------------------------------------------------------------
    # Prediction
    # ------------------------------------------------------------------

    def analyze_email(
        self, analysis_id: str, parsed_email_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Run ML prediction on parsed email data.

        Args:
            analysis_id: UUID of the AnalysisJob.
            parsed_email_data: Dict with keys like ``from``, ``subject``,
                ``body_text``, ``authentication_results``, ``urls``, etc.

        Returns:
            Prediction result dict with prediction, confidence, reasoning.
        """
        if not self.classifier.is_trained:
            logger.info("ml_model_not_trained", analysis_id=analysis_id)
            return {
                "prediction": "UNKNOWN",
                "confidence": 0.0,
                "reasoning": "ML model not available",
                "stage": "unavailable",
            }

        try:
            features = self.feature_extractor.extract_all_features(parsed_email_data)
            from_domain = self._extract_domain(parsed_email_data.get("from", ""))
            features["_from_domain"] = from_domain

            result = self.classifier.predict(features)
            self._save_prediction(analysis_id, result, features)
            return result

        except Exception as exc:
            logger.error("ml_analysis_failed", analysis_id=analysis_id, error=str(exc))
            return {
                "prediction": "ERROR",
                "confidence": 0.0,
                "reasoning": f"ML analysis failed: {exc}",
                "stage": "error",
            }

    def _save_prediction(
        self, analysis_id: str, result: Dict, features: Dict,
    ) -> None:
        """Persist ML prediction to the database."""
        db = SessionLocal()
        try:
            # Remove internal keys before storing
            storable_features = {k: v for k, v in features.items() if not k.startswith("_")}

            prediction = MLPrediction(
                analysis_id=analysis_id,
                prediction=result["prediction"],
                confidence=result["confidence"],
                phishing_probability=result.get("phishing_probability", 0.0),
                legitimate_probability=result.get("legitimate_probability", 0.0),
                model_version=result.get("model_version", "unknown"),
                reasoning=result.get("reasoning", ""),
                stage=result.get("stage", ""),
                features_json=storable_features,
            )
            db.add(prediction)
            db.commit()
        except Exception as exc:
            db.rollback()
            logger.error("ml_prediction_save_failed", error=str(exc))
        finally:
            db.close()

    # ------------------------------------------------------------------
    # Feedback
    # ------------------------------------------------------------------

    def record_feedback(
        self, analysis_id: str, user_label: str, notes: Optional[str] = None,
    ) -> None:
        """Record user feedback on an ML prediction.

        If the prediction was a false positive and 3+ false positives occur
        from the same domain, the domain is auto-whitelisted.

        Args:
            analysis_id: UUID of the AnalysisJob.
            user_label: ``"PHISHING"`` or ``"LEGITIMATE"``.
            notes: Optional freeform feedback notes.
        """
        db = SessionLocal()
        try:
            prediction = (
                db.query(MLPrediction)
                .filter(MLPrediction.analysis_id == analysis_id)
                .order_by(MLPrediction.created_at.desc())
                .first()
            )

            if not prediction:
                logger.warning("ml_feedback_no_prediction", analysis_id=analysis_id)
                return

            was_correct = (
                (prediction.prediction == "PHISHING" and user_label == "PHISHING")
                or (prediction.prediction == "SAFE" and user_label == "LEGITIMATE")
            )

            feedback = MLFeedback(
                prediction_id=prediction.id,
                user_label=user_label,
                was_correct=was_correct,
                feedback_notes=notes,
            )
            db.add(feedback)
            db.commit()

            logger.info(
                "ml_feedback_recorded",
                analysis_id=analysis_id,
                user_label=user_label,
                was_correct=was_correct,
            )

            if user_label == "LEGITIMATE" and not was_correct:
                self._handle_false_positive(analysis_id, db)

        except Exception as exc:
            db.rollback()
            logger.error("ml_feedback_failed", error=str(exc))
        finally:
            db.close()

    def _handle_false_positive(self, analysis_id: str, db) -> None:
        """Potentially auto-whitelist a domain after repeated false positives."""
        try:
            parsed = (
                db.query(ParsedEmail)
                .filter(ParsedEmail.analysis_id == analysis_id)
                .first()
            )
            if not parsed or not parsed.sender:
                return

            from_domain = self._extract_domain(parsed.sender)
            if not from_domain:
                return

            existing = (
                db.query(DomainWhitelist)
                .filter(DomainWhitelist.domain == from_domain)
                .first()
            )

            if existing:
                existing.confirmation_count += 1
                existing.confidence_score = min(1.0, existing.confidence_score + 0.1)
                db.commit()
            else:
                # Count false positives from this domain across all analyses
                fp_count = (
                    db.query(MLFeedback)
                    .join(MLPrediction)
                    .join(ParsedEmail, MLPrediction.analysis_id == ParsedEmail.analysis_id)
                    .filter(
                        ParsedEmail.sender.contains(from_domain),
                        MLFeedback.user_label == "LEGITIMATE",
                        MLFeedback.was_correct == False,  # noqa: E712
                    )
                    .count()
                )

                if fp_count >= 3:
                    whitelist_entry = DomainWhitelist(
                        domain=from_domain,
                        confidence_score=0.8,
                        added_by="auto",
                        confirmation_count=fp_count,
                    )
                    db.add(whitelist_entry)
                    db.commit()
                    self.classifier.add_to_whitelist(from_domain)
                    logger.info("domain_auto_whitelisted", domain=from_domain, fp_count=fp_count)

        except Exception as exc:
            logger.error("false_positive_handling_failed", error=str(exc))

    # ------------------------------------------------------------------
    # Model management
    # ------------------------------------------------------------------

    def reload_model(self, model_path: Optional[str] = None) -> None:
        """Reload the ML model (e.g. after retraining)."""
        if model_path is None:
            model_path = str(Path(settings.ml_model_path) / "ensemble_model_v1.pkl")

        self.classifier.load_model(model_path)
        self._load_lists_from_db()
        logger.info("ml_model_reloaded", path=model_path)

    def get_model_stats(self) -> Dict[str, Any]:
        """Return current model performance statistics from feedback data."""
        db = SessionLocal()
        try:
            total_predictions = db.query(MLPrediction).count()
            total_feedback = db.query(MLFeedback).count()

            correct = db.query(MLFeedback).filter(MLFeedback.was_correct == True).count()  # noqa: E712
            accuracy = correct / total_feedback if total_feedback > 0 else 0.0

            false_positives = (
                db.query(MLFeedback)
                .filter(
                    MLFeedback.was_correct == False,  # noqa: E712
                    MLFeedback.user_label == "LEGITIMATE",
                )
                .count()
            )
            fp_rate = false_positives / total_feedback if total_feedback > 0 else 0.0

            return {
                "total_predictions": total_predictions,
                "total_feedback": total_feedback,
                "accuracy": accuracy,
                "false_positive_rate": fp_rate,
                "model_version": self.classifier.model_version,
                "model_trained": self.classifier.is_trained,
                "whitelisted_domains": len(self.classifier.whitelisted_domains),
                "blacklisted_domains": len(self.classifier.blacklisted_domains),
            }
        finally:
            db.close()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_domain(email_or_url: str) -> str:
        match = re.search(r"@([^\s>]+)", email_or_url)
        return match.group(1).lower() if match else ""


def get_ml_integration() -> MLIntegration:
    """Return the MLIntegration singleton."""
    return MLIntegration()
