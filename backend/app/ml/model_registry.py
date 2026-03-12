"""
PhisMail — Model Registry
Versioned model storage and retrieval using the MLModel database table.
"""

import os
from datetime import datetime
from typing import Optional

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.models import MLModel

logger = get_logger(__name__)
settings = get_settings()


class ModelRegistry:
    """Manages versioned ML model storage, retrieval, and lifecycle.

    Persists model metadata in the MLModel database table and serialises
    model objects to disk via joblib.
    """

    def __init__(
        self,
        db_session,
        model_path: Optional[str] = None,
    ) -> None:
        """Initialise the registry.

        Args:
            db_session: An open SQLAlchemy Session instance.
            model_path: Directory where serialised model files are stored.
                Defaults to ``settings.ml_model_path``.
        """
        self.db = db_session
        self.model_path: str = model_path or settings.ml_model_path
        os.makedirs(self.model_path, exist_ok=True)

    # ------------------------------------------------------------------
    # Write operations
    # ------------------------------------------------------------------

    def register(
        self,
        name: str,
        version: str,
        accuracy: float,
        precision: float,
        recall: float,
        model_obj=None,
    ) -> MLModel:
        """Register a new model version in the database.

        If *model_obj* is provided it is serialised with joblib to
        ``{model_path}/{name}_{version}.joblib`` and the path is stored on
        the record.

        Args:
            name: Logical model name (e.g. ``"phishing_rf"``).
            version: Semantic version string (e.g. ``"1.2.0"``).
            accuracy: Accuracy score on the test set (0–1).
            precision: Precision score on the test set (0–1).
            recall: Recall score on the test set (0–1).
            model_obj: Optional fitted scikit-learn / XGBoost model to
                serialise.  Pass ``None`` to register metadata only.

        Returns:
            The persisted :class:`~app.models.models.MLModel` ORM object.
        """
        file_path: Optional[str] = None

        if model_obj is not None:
            import joblib

            filename = f"{name}_{version}.joblib"
            file_path = os.path.join(self.model_path, filename)
            try:
                joblib.dump(model_obj, file_path)
                logger.info(
                    "model_serialised",
                    name=name,
                    version=version,
                    path=file_path,
                )
            except Exception as exc:
                logger.error(
                    "model_serialisation_failed",
                    name=name,
                    version=version,
                    error=str(exc),
                )
                file_path = None

        ml_model = MLModel(
            model_name=name,
            model_version=version,
            model_path=file_path,
            training_date=datetime.utcnow(),
            accuracy_score=accuracy,
            metadata_json={
                "precision": precision,
                "recall": recall,
            },
            is_active=True,
        )

        self.db.add(ml_model)
        self.db.commit()
        self.db.refresh(ml_model)

        logger.info(
            "model_registered",
            name=name,
            version=version,
            model_id=ml_model.id,
            accuracy=accuracy,
        )
        return ml_model

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    def get_latest(self, name: str) -> Optional[MLModel]:
        """Return the most recently trained model with the given name.

        Args:
            name: Logical model name to search for.

        Returns:
            The newest :class:`~app.models.models.MLModel` record, or
            ``None`` if none exists.
        """
        model = (
            self.db.query(MLModel)
            .filter(MLModel.model_name == name)
            .order_by(MLModel.training_date.desc())
            .first()
        )
        if model is None:
            logger.debug("model_not_found", name=name)
        return model

    def get_by_version(self, name: str, version: str) -> Optional[MLModel]:
        """Return a specific model by name and version.

        Args:
            name: Logical model name.
            version: Exact version string.

        Returns:
            Matching :class:`~app.models.models.MLModel` record or ``None``.
        """
        return (
            self.db.query(MLModel)
            .filter(
                MLModel.model_name == name,
                MLModel.model_version == version,
            )
            .first()
        )

    def load_model(self, ml_model: MLModel):
        """Deserialise a model from disk.

        Args:
            ml_model: An :class:`~app.models.models.MLModel` ORM record
                whose ``model_path`` points to a joblib file.

        Returns:
            The deserialised model object, or ``None`` if the file is
            missing or deserialization fails.
        """
        if not ml_model.model_path or not os.path.exists(ml_model.model_path):
            logger.warning(
                "model_file_missing",
                name=ml_model.model_name,
                version=ml_model.model_version,
                path=ml_model.model_path,
            )
            return None

        try:
            import joblib

            model_obj = joblib.load(ml_model.model_path)
            logger.info(
                "model_loaded",
                name=ml_model.model_name,
                version=ml_model.model_version,
                path=ml_model.model_path,
            )
            return model_obj
        except Exception as exc:
            logger.error(
                "model_load_failed",
                name=ml_model.model_name,
                version=ml_model.model_version,
                error=str(exc),
            )
            return None

    def list_models(self) -> list[MLModel]:
        """Return all registered models ordered by training date (newest first).

        Returns:
            List of :class:`~app.models.models.MLModel` records.
        """
        return (
            self.db.query(MLModel)
            .order_by(MLModel.training_date.desc())
            .all()
        )

    # ------------------------------------------------------------------
    # Lifecycle management
    # ------------------------------------------------------------------

    def deactivate_old_versions(
        self, name: str, keep_latest: int = 2
    ) -> None:
        """Deactivate older model versions beyond the *keep_latest* count.

        Sets ``is_active = False`` on all records for *name* that fall
        outside the most recent *keep_latest* entries.

        Args:
            name: Logical model name.
            keep_latest: Number of most-recent versions to keep active.
        """
        models = (
            self.db.query(MLModel)
            .filter(MLModel.model_name == name)
            .order_by(MLModel.training_date.desc())
            .all()
        )

        deactivated = 0
        for idx, ml_model in enumerate(models):
            if idx >= keep_latest and ml_model.is_active:
                ml_model.is_active = False
                deactivated += 1

        if deactivated:
            self.db.commit()
            logger.info(
                "old_model_versions_deactivated",
                name=name,
                deactivated=deactivated,
                kept=keep_latest,
            )
