"""
PhisMail — Feature Loader
Loads feature vectors from the database for ML model training.
"""

from typing import Optional
from app.core.logging import get_logger
from app.models.models import FeatureVector, InvestigationReport, Verdict

logger = get_logger(__name__)


class FeatureLoader:
    """Loads and transforms feature vectors from the database for ML training.

    Queries the FeatureVector table, pivots row-per-feature storage into
    per-analysis feature dicts, and optionally joins labels from
    InvestigationReport for supervised training.
    """

    def __init__(self, db_session) -> None:
        """Initialise with an active SQLAlchemy session.

        Args:
            db_session: An open SQLAlchemy Session instance.
        """
        self.db = db_session

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def load_features(
        self, limit: int = 10000
    ) -> tuple[list[dict], list[str]]:
        """Load feature vectors for all analyses, up to *limit* rows.

        Queries FeatureVector rows ordered by analysis_id and pivots them
        into one dict per analysis_id where keys are feature names and
        values are feature values (float).

        Args:
            limit: Maximum number of analysis IDs to include.

        Returns:
            A 2-tuple of:
            - feature_dicts: list of dicts mapping feature_name → feature_value
            - analysis_ids: list of analysis_id strings in the same order
        """
        rows = (
            self.db.query(FeatureVector)
            .order_by(FeatureVector.analysis_id)
            .all()
        )

        feature_dicts, analysis_ids = self._pivot_rows(rows, limit=limit)

        logger.info(
            "features_loaded",
            n_analyses=len(analysis_ids),
            limit=limit,
        )
        return feature_dicts, analysis_ids

    def load_labeled_features(
        self,
    ) -> tuple[list[dict], list[int], list[str]]:
        """Load feature vectors joined with ground-truth labels.

        Only analyses that have a completed InvestigationReport are included.
        The label is 1 when the verdict is PHISHING, 0 otherwise.

        Returns:
            A 3-tuple of:
            - feature_dicts: list of dicts mapping feature_name → feature_value
            - labels: list of int (1 = phishing, 0 = safe/suspicious)
            - analysis_ids: list of analysis_id strings in the same order
        """
        rows = (
            self.db.query(FeatureVector)
            .join(
                InvestigationReport,
                FeatureVector.analysis_id == InvestigationReport.analysis_id,
            )
            .order_by(FeatureVector.analysis_id)
            .all()
        )

        feature_dicts, analysis_ids = self._pivot_rows(rows)

        # Fetch verdicts for all collected analysis IDs in one query
        reports = (
            self.db.query(
                InvestigationReport.analysis_id,
                InvestigationReport.verdict,
            )
            .filter(
                InvestigationReport.analysis_id.in_(analysis_ids)
            )
            .all()
        )
        verdict_map: dict[str, str] = {r.analysis_id: r.verdict for r in reports}

        labels: list[int] = [
            1 if verdict_map.get(aid) == Verdict.PHISHING else 0
            for aid in analysis_ids
        ]

        logger.info(
            "labeled_features_loaded",
            n_analyses=len(analysis_ids),
            n_phishing=sum(labels),
            n_benign=len(labels) - sum(labels),
        )
        return feature_dicts, labels, analysis_ids

    def get_feature_names(self) -> list[str]:
        """Return a sorted list of all distinct feature names in the store.

        Returns:
            Sorted list of unique feature_name strings.
        """
        rows = (
            self.db.query(FeatureVector.feature_name)
            .distinct()
            .all()
        )
        names = sorted(r.feature_name for r in rows)
        logger.debug("feature_names_retrieved", count=len(names))
        return names

    def to_feature_matrix(
        self,
        feature_dicts: list[dict],
        feature_names: list[str],
    ) -> list[list[float]]:
        """Convert a list of feature dicts into a dense 2-D float matrix.

        Missing features in a given dict are filled with 0.0.

        Args:
            feature_dicts: Output of :meth:`load_features` or
                :meth:`load_labeled_features`.
            feature_names: Ordered list of feature names defining columns.

        Returns:
            A list of rows, each row being a list of floats aligned to
            *feature_names*.
        """
        matrix: list[list[float]] = [
            [float(fd.get(name, 0.0)) for name in feature_names]
            for fd in feature_dicts
        ]
        logger.debug(
            "feature_matrix_built",
            n_rows=len(matrix),
            n_cols=len(feature_names),
        )
        return matrix

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _pivot_rows(
        self,
        rows: list,
        limit: Optional[int] = None,
    ) -> tuple[list[dict], list[str]]:
        """Pivot a flat list of FeatureVector ORM objects into per-analysis dicts.

        Args:
            rows: Ordered list of FeatureVector instances.
            limit: If set, stop after this many distinct analysis IDs.

        Returns:
            (feature_dicts, analysis_ids) with one entry per analysis.
        """
        grouped: dict[str, dict[str, float]] = {}
        order: list[str] = []

        for row in rows:
            aid = row.analysis_id
            if aid not in grouped:
                if limit is not None and len(grouped) >= limit:
                    break
                grouped[aid] = {}
                order.append(aid)
            grouped[aid][row.feature_name] = float(row.feature_value)

        feature_dicts = [grouped[aid] for aid in order]
        return feature_dicts, order
