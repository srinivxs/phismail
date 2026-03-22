"""
PhisMail — Ensemble Model Trainer
Training pipeline for the RF + GB ensemble classifier.
Run: python -m app.ml.ensemble_trainer
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from app.core.config import get_settings
from app.core.logging import get_logger
from app.ml.feature_extractor import EmailFeatureExtractor
from app.ml.ensemble_classifier import EnsemblePhishingClassifier

logger = get_logger(__name__)
settings = get_settings()


class EnsembleTrainer:
    """Complete training pipeline for the ensemble phishing classifier.

    Supports data from CSV files and/or the PhisMail database.
    """

    def __init__(self, data_dir: str = "data/training") -> None:
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.feature_extractor = EmailFeatureExtractor()
        self.classifier = EnsemblePhishingClassifier()

    # ------------------------------------------------------------------
    # Data collection
    # ------------------------------------------------------------------

    def collect_training_data(self) -> Tuple[List[Dict], List[int]]:
        """Collect training data from CSV files and optionally from the DB.

        Returns:
            (email_data_list, labels_list)
        """
        emails: List[Dict] = []
        labels: List[int] = []

        # CSV sources
        phishing_csv = self.data_dir / "phishing_emails.csv"
        legitimate_csv = self.data_dir / "legitimate_emails.csv"

        if phishing_csv.exists():
            df = pd.read_csv(phishing_csv)
            for _, row in df.iterrows():
                emails.append(self._csv_row_to_dict(row))
                labels.append(1)
            logger.info("phishing_csv_loaded", count=len(df))

        if legitimate_csv.exists():
            df = pd.read_csv(legitimate_csv)
            for _, row in df.iterrows():
                emails.append(self._csv_row_to_dict(row))
                labels.append(0)
            logger.info("legitimate_csv_loaded", count=len(df))

        # DB source (labeled features from feedback)
        db_emails, db_labels = self._load_from_database()
        emails.extend(db_emails)
        labels.extend(db_labels)

        logger.info(
            "training_data_collected",
            total=len(emails),
            phishing=sum(labels),
            legitimate=len(labels) - sum(labels),
        )
        return emails, labels

    def _csv_row_to_dict(self, row: pd.Series) -> Dict:
        return {
            "from": row.get("from", row.get("sender", "")),
            "return_path": row.get("return_path", ""),
            "reply_to": row.get("reply_to", ""),
            "subject": row.get("subject", ""),
            "body_text": row.get("body", row.get("body_text", "")),
            "body_html": row.get("body_html", ""),
            "authentication_results": row.get("authentication_results", ""),
            "urls": self._parse_urls(row.get("urls", "")),
            "received_headers": self._parse_list(row.get("received_headers", "")),
            "message_id": row.get("message_id", ""),
            "x_mailer": row.get("x_mailer", ""),
            "list_unsubscribe": row.get("list_unsubscribe", ""),
            "attachments": self._parse_list(row.get("attachments", "")),
        }

    def _parse_urls(self, url_string) -> List[str]:
        if pd.isna(url_string) or not url_string:
            return []
        return [u.strip() for u in str(url_string).replace("\n", ",").split(",") if u.strip()]

    def _parse_list(self, list_string) -> List[str]:
        if pd.isna(list_string) or not list_string:
            return []
        return [s.strip() for s in str(list_string).split(",") if s.strip()]

    def _load_from_database(self) -> Tuple[List[Dict], List[int]]:
        """Load confirmed emails from the DB via ML feedback."""
        try:
            from app.core.database import SessionLocal
            from app.models.models import MLFeedback, MLPrediction

            db = SessionLocal()
            try:
                feedback_rows = (
                    db.query(MLFeedback, MLPrediction)
                    .join(MLPrediction)
                    .filter(MLFeedback.user_label.isnot(None))
                    .all()
                )

                if not feedback_rows:
                    return [], []

                emails = []
                labels = []
                for feedback, prediction in feedback_rows:
                    if prediction.features_json:
                        emails.append(prediction.features_json)
                        labels.append(1 if feedback.user_label == "PHISHING" else 0)

                logger.info("db_feedback_loaded", count=len(emails))
                return emails, labels
            finally:
                db.close()

        except Exception as exc:
            logger.warning("db_feedback_load_failed", error=str(exc))
            return [], []

    # ------------------------------------------------------------------
    # Feature extraction
    # ------------------------------------------------------------------

    def extract_features(self, emails: List[Dict]) -> Tuple[np.ndarray, List[str]]:
        """Extract features from all email dicts."""
        all_features = []
        feature_names: Optional[List[str]] = None

        for email in emails:
            features = self.feature_extractor.extract_all_features(email)
            if feature_names is None:
                feature_names = sorted(features.keys())
            all_features.append([features.get(n, 0) for n in feature_names])

        X = np.array(all_features)
        return X, feature_names or []

    # ------------------------------------------------------------------
    # Full pipeline
    # ------------------------------------------------------------------

    def run_training_pipeline(
        self, model_save_path: Optional[str] = None,
    ) -> Optional[Dict]:
        """Run the complete training pipeline.

        Returns:
            Training metrics dict, or None if insufficient data.
        """
        if model_save_path is None:
            model_save_path = str(
                Path(settings.ml_model_path) / "ensemble_model_v1.pkl"
            )

        emails, labels = self.collect_training_data()
        if len(emails) < 6:
            print(f"[WARNING] Only {len(emails)} samples. Need at least 6. Aborting.")
            return None

        X, feature_names = self.extract_features(emails)
        y = np.array(labels)

        metrics = self.classifier.train(
            X, y, feature_names=feature_names, use_smote=True,
        )

        self._print_report(metrics)

        save_path = Path(model_save_path)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        self.classifier.save_model(str(save_path))

        # Save report JSON
        self._save_report(metrics, save_path)

        return metrics

    def _print_report(self, metrics: Dict) -> None:
        print("\n" + "=" * 60)
        print("ENSEMBLE TRAINING REPORT")
        print("=" * 60)

        for name in ["rf_metrics", "gb_metrics", "ensemble_metrics"]:
            m = metrics[name]
            print(f"\n{name.replace('_', ' ').upper()}")
            print("-" * 40)
            print(f"Accuracy:     {m['accuracy']:.4f}")
            print(f"Precision:    {m['precision']:.4f}")
            print(f"Recall:       {m['recall']:.4f}")
            print(f"F1 Score:     {m['f1_score']:.4f}")
            print(f"AUC-ROC:      {m['auc_roc']:.4f}")
            print(f"FP Rate:      {m['false_positive_rate']:.4f}")

        print(f"\nCV AUC: {metrics['cv_mean_auc']:.4f} +/- {metrics['cv_std_auc']:.4f}")

        top = self.classifier.get_feature_importance(top_n=10)
        if top:
            print("\nTOP 10 FEATURES")
            print("-" * 40)
            for feat, imp in top.items():
                print(f"  {feat:30s} {imp:.4f}")

    def _save_report(self, metrics: Dict, model_path: Path) -> None:
        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "model_version": self.classifier.model_version,
            "metrics": self._to_python(metrics),
            "feature_importance": self._to_python(self.classifier.feature_importances),
        }
        report_path = model_path.parent / f"{model_path.stem}_report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

    def _to_python(self, obj):
        """Convert numpy types to native Python for JSON serialization."""
        if isinstance(obj, dict):
            return {k: self._to_python(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self._to_python(i) for i in obj]
        if isinstance(obj, (np.integer,)):
            return int(obj)
        if isinstance(obj, (np.floating,)):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        return obj


# ---------------------------------------------------------------------------
# Sample data generator
# ---------------------------------------------------------------------------

def create_sample_training_data(data_dir: str = "data/training") -> None:
    """Create sample CSV files for bootstrapping model training."""
    data_path = Path(data_dir)
    data_path.mkdir(parents=True, exist_ok=True)

    phishing = pd.DataFrame({
        "from": [
            "security@paypa1.com",
            "Apple Support <noreply@apple-security.tk>",
            "admin@bank0famerica.com",
        ],
        "subject": [
            "Urgent: Verify your account immediately",
            "Your Apple ID has been suspended",
            "Unusual activity detected on your account",
        ],
        "body_text": [
            "Click here to verify: http://paypal.com.phishing.tk/verify",
            "Your account will be locked. Click here: http://192.168.1.1/apple",
            "Please confirm your identity: http://bit.ly/12345",
        ],
        "authentication_results": [
            "spf=fail dkim=fail dmarc=fail",
            "spf=none dkim=none dmarc=none",
            "spf=fail dkim=pass dmarc=fail",
        ],
        "urls": [
            "http://paypal.com.phishing.tk/verify",
            "http://192.168.1.1/apple",
            "http://bit.ly/12345,http://bankofamerica.tk/login",
        ],
    })

    legitimate = pd.DataFrame({
        "from": [
            "The Souled Store <connect@hello.thesouledstore.com>",
            "GitHub <noreply@github.com>",
            "Amazon <no-reply@amazon.com>",
        ],
        "subject": [
            "Fresh Fits Alert: New Collection",
            "Your pull request was merged",
            "Your Amazon order has shipped",
        ],
        "body_text": [
            "Check out our new pants collection at thesouledstore.com",
            "Pull request #123 in your repository was successfully merged",
            "Your order #456 will arrive tomorrow",
        ],
        "authentication_results": [
            "spf=pass dkim=pass dmarc=pass",
            "spf=pass dkim=pass dmarc=pass",
            "spf=pass dkim=pass dmarc=pass",
        ],
        "urls": [
            "https://www.thesouledstore.com/collection,https://elink.hello.thesouledstore.com/track",
            "https://github.com/user/repo/pull/123",
            "https://www.amazon.com/orders/456,https://track.amazon.com/tracking",
        ],
        "list_unsubscribe": [
            "mailto:unsubscribe@thesouledstore.com",
            "https://github.com/notifications/unsubscribe",
            "https://www.amazon.com/gp/communications/unsubscribe",
        ],
    })

    phishing.to_csv(data_path / "phishing_emails.csv", index=False)
    legitimate.to_csv(data_path / "legitimate_emails.csv", index=False)
    print(f"[INFO] Sample training data created in {data_path}/")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train PhisMail ensemble classifier.")
    parser.add_argument(
        "--create-sample-data", action="store_true",
        help="Create sample CSV training data and exit.",
    )
    parser.add_argument(
        "--data-dir", default="data/training",
        help="Directory containing training CSVs (default: data/training).",
    )
    parser.add_argument(
        "--model-path", default=None,
        help="Path to save trained model (default: ml_models/ensemble_model_v1.pkl).",
    )

    args = parser.parse_args()

    if args.create_sample_data:
        create_sample_training_data(args.data_dir)
        sys.exit(0)

    trainer = EnsembleTrainer(data_dir=args.data_dir)
    result = trainer.run_training_pipeline(model_save_path=args.model_path)

    if result is None:
        sys.exit(1)
