"""
PhisMail — Model Training Script
Trains a RandomForest/XGBoost classifier on labeled feature vectors.
Run: python -m app.ml.train
"""

import argparse
import sys
from typing import Optional

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()


def train_model(
    model_type: str = "random_forest",
    test_size: float = 0.2,
    n_estimators: int = 100,
) -> Optional[dict]:
    """Train a phishing classifier on labeled feature vectors from the DB.

    Pulls features and ground-truth labels via :class:`~app.ml.feature_loader.FeatureLoader`,
    splits the dataset, fits the chosen estimator, evaluates it, then
    registers the resulting model via :class:`~app.ml.model_registry.ModelRegistry`.

    Args:
        model_type: One of ``"random_forest"`` or ``"xgboost"``.
        test_size: Fraction of samples reserved for the test split (0–1).
        n_estimators: Number of trees / boosting rounds.

    Returns:
        A dict with keys ``accuracy``, ``precision``, ``recall``, ``f1``,
        ``n_train``, ``n_test``, ``n_features``, ``model_version``, or
        ``None`` if there are not enough labeled samples.
    """
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score

    from app.core.database import SessionLocal
    from app.ml.feature_loader import FeatureLoader
    from app.ml.model_registry import ModelRegistry

    db = SessionLocal()
    try:
        # -----------------------------------------------------------------
        # 1. Load labeled features
        # -----------------------------------------------------------------
        loader = FeatureLoader(db)
        feature_dicts, labels, analysis_ids = loader.load_labeled_features()

        n_samples = len(feature_dicts)
        if n_samples < 10:
            print(
                f"[WARNING] Only {n_samples} labeled samples available. "
                "At least 10 are required to train a model. Aborting."
            )
            logger.warning(
                "training_aborted_insufficient_samples",
                n_samples=n_samples,
                required=10,
            )
            return None

        print(f"[INFO] Loaded {n_samples} labeled samples.")

        # -----------------------------------------------------------------
        # 2. Build feature matrix
        # -----------------------------------------------------------------
        feature_names = loader.get_feature_names()
        n_features = len(feature_names)
        print(f"[INFO] Feature space: {n_features} features.")

        X_list = loader.to_feature_matrix(feature_dicts, feature_names)
        X = np.array(X_list, dtype=np.float32)
        y = np.array(labels, dtype=np.int32)

        # -----------------------------------------------------------------
        # 3. Train / test split
        # -----------------------------------------------------------------
        X_train, X_test, y_train, y_test = train_test_split(
            X,
            y,
            test_size=test_size,
            random_state=settings.ml_random_seed,
            stratify=y if len(set(y)) > 1 else None,
        )
        print(
            f"[INFO] Split — train: {len(X_train)}, test: {len(X_test)}."
        )

        # -----------------------------------------------------------------
        # 4. Fit model
        # -----------------------------------------------------------------
        if model_type == "xgboost":
            try:
                from xgboost import XGBClassifier

                clf = XGBClassifier(
                    n_estimators=n_estimators,
                    random_state=settings.ml_random_seed,
                    use_label_encoder=False,
                    eval_metric="logloss",
                    verbosity=0,
                )
                model_name_label = "phishing_xgb"
            except ImportError:
                print(
                    "[WARNING] xgboost not installed. Falling back to RandomForest."
                )
                logger.warning("xgboost_not_available_fallback_rf")
                clf = RandomForestClassifier(
                    n_estimators=n_estimators,
                    random_state=settings.ml_random_seed,
                    n_jobs=-1,
                )
                model_name_label = "phishing_rf"
        else:
            clf = RandomForestClassifier(
                n_estimators=n_estimators,
                random_state=settings.ml_random_seed,
                n_jobs=-1,
            )
            model_name_label = "phishing_rf"

        print(f"[INFO] Training {model_name_label} …")
        clf.fit(X_train, y_train)
        print("[INFO] Training complete.")

        # -----------------------------------------------------------------
        # 5. Evaluate
        # -----------------------------------------------------------------
        y_pred = clf.predict(X_test)

        acc = float(accuracy_score(y_test, y_pred))
        prec = float(
            precision_score(y_test, y_pred, zero_division=0)
        )
        rec = float(recall_score(y_test, y_pred, zero_division=0))
        f1 = float(f1_score(y_test, y_pred, zero_division=0))

        report_str = classification_report(
            y_test, y_pred, target_names=["benign", "phishing"]
        )
        print("\n[INFO] Classification report:\n" + report_str)

        metrics = {
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1": f1,
            "n_train": int(len(X_train)),
            "n_test": int(len(X_test)),
            "n_features": n_features,
        }

        # -----------------------------------------------------------------
        # 6. Register model
        # -----------------------------------------------------------------
        import datetime

        version = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        metrics["model_version"] = version

        registry = ModelRegistry(db)
        ml_model = registry.register(
            name=model_name_label,
            version=version,
            accuracy=acc,
            precision=prec,
            recall=rec,
            model_obj=clf,
        )
        registry.deactivate_old_versions(model_name_label, keep_latest=2)

        print(
            f"\n[INFO] Model registered: id={ml_model.id}, "
            f"version={version}, accuracy={acc:.4f}"
        )
        logger.info(
            "training_completed",
            model_name=model_name_label,
            version=version,
            accuracy=acc,
            precision=prec,
            recall=rec,
            f1=f1,
        )

        return metrics

    finally:
        db.close()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Train a PhisMail phishing classifier.",
    )
    parser.add_argument(
        "--model-type",
        default="random_forest",
        choices=["random_forest", "xgboost"],
        help="Classifier type (default: random_forest)",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Fraction of samples for the test split (default: 0.2)",
    )
    parser.add_argument(
        "--n-estimators",
        type=int,
        default=100,
        help="Number of estimators / boosting rounds (default: 100)",
    )

    args = parser.parse_args()

    print(
        f"[INFO] Starting training: model_type={args.model_type}, "
        f"test_size={args.test_size}, n_estimators={args.n_estimators}"
    )

    result = train_model(
        model_type=args.model_type,
        test_size=args.test_size,
        n_estimators=args.n_estimators,
    )

    if result is None:
        sys.exit(1)

    print("\n[INFO] Final metrics:")
    for key, value in result.items():
        print(f"  {key}: {value}")
