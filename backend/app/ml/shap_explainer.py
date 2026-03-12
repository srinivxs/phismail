"""
PhisMail — SHAP Explainer
Feature attribution for model explainability.
"""

from typing import Dict, List, Optional
from app.core.logging import get_logger

logger = get_logger(__name__)


def explain_prediction(
    features: Dict[str, float],
    risk_result=None,
    top_n: int = 10,
) -> List[Dict]:
    """Generate SHAP-like feature attributions.

    Currently uses the rule engine's contribution analysis.
    When a trained model is available, this will use actual SHAP values.
    """

    if risk_result and hasattr(risk_result, "top_contributors"):
        return risk_result.top_contributors[:top_n]

    # Fallback: sort features by absolute value
    sorted_features = sorted(
        features.items(),
        key=lambda x: abs(x[1]),
        reverse=True,
    )

    return [
        {
            "feature_name": name,
            "attribution_score": value,
            "direction": "phishing" if value > 0 else "safe",
        }
        for name, value in sorted_features[:top_n]
    ]
