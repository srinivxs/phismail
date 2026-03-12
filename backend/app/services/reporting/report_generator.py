"""
PhisMail — Report Generator
Assembles the structured investigation report from all analysis results.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime

from app.core.logging import get_logger, LogEvents

logger = get_logger(__name__)


def generate_report(
    analysis_id: str,
    risk_result: Any,
    features: Dict[str, float],
    parsed_email: Optional[Any] = None,
    url_results: Optional[List[Any]] = None,
    domain_results: Optional[List[Dict]] = None,
    threat_results: Optional[List[Dict]] = None,
) -> Dict[str, Any]:
    """Generate a structured investigation report."""

    report = {
        "analysis_id": analysis_id,
        "verdict": risk_result.verdict,
        "risk_score": round(risk_result.risk_score, 2),
        "generated_at": datetime.utcnow().isoformat(),

        # Indicators sorted by severity
        "indicators": risk_result.indicators,

        # SHAP explainability
        "top_contributors": risk_result.top_contributors,

        # Feature summary
        "feature_summary": {
            "total_features": len(features),
            "risk_contributing_features": sum(
                1 for v in features.values() if v > 0
            ),
        },

        # Email info (if applicable)
        "email_info": None,

        # URL analysis
        "url_analysis": [],

        # Domain intelligence
        "domain_intelligence": domain_results or [],

        # Threat intelligence hits
        "threat_intel_hits": threat_results or [],
    }

    # Add email info
    if parsed_email:
        report["email_info"] = {
            "sender": getattr(parsed_email, "sender", None),
            "reply_to": getattr(parsed_email, "reply_to", None),
            "subject": getattr(parsed_email, "subject", None),
            "attachment_count": len(getattr(parsed_email, "attachments", [])),
            "originating_ip": getattr(parsed_email, "originating_ip", None),
        }

    # Add URL analysis results
    if url_results:
        for url_r in url_results:
            report["url_analysis"].append({
                "url": getattr(url_r, "url", ""),
                "domain": getattr(url_r, "domain", ""),
                "entropy_score": getattr(url_r, "entropy_score", 0),
                "is_shortened": getattr(url_r, "is_shortened", False),
                "contains_ip": getattr(url_r, "contains_ip", False),
                "brand_keyword": getattr(url_r, "detected_brand", None),
            })

    logger.info(
        LogEvents.REPORT_GENERATED,
        analysis_id=analysis_id,
        verdict=risk_result.verdict,
        risk_score=round(risk_result.risk_score, 2),
        indicator_count=len(risk_result.indicators),
    )

    return report
