"""
PhisMail — Report Worker
Report generation and persistence tasks.
"""

from datetime import datetime

from app.core.celery_app import celery_app
from app.core.database import SessionLocal
from app.core.logging import get_logger, LogEvents
from app.models.models import (
    AnalysisJob, AnalysisStatus, FeatureVector, Indicator,
    InvestigationReport, Verdict,
)
from app.services.reporting.report_generator import generate_report
from app.services.risk_scoring.rule_engine import calculate_risk_score

logger = get_logger(__name__)


@celery_app.task(bind=True, max_retries=2, default_retry_delay=5, queue='reports')
def generate_report_task(self, analysis_id: str) -> dict:
    """Generate and persist the final investigation report for an analysis."""

    db = SessionLocal()

    try:
        logger.info(
            LogEvents.WORKER_TASK_STARTED,
            task="generate_report_task",
            analysis_id=analysis_id,
        )

        job = db.query(AnalysisJob).filter(AnalysisJob.id == analysis_id).first()
        if not job:
            logger.error("analysis_job_not_found", analysis_id=analysis_id)
            return {"analysis_id": analysis_id, "error": "job_not_found"}

        # Load feature vectors and indicators saved by scoring_worker
        feature_rows = (
            db.query(FeatureVector)
            .filter(FeatureVector.analysis_id == analysis_id)
            .all()
        )
        indicators = (
            db.query(Indicator)
            .filter(Indicator.analysis_id == analysis_id)
            .all()
        )

        # Build features dict from persisted FeatureVector rows
        features = {row.feature_name: row.feature_value for row in feature_rows}

        # Check if an InvestigationReport already exists (upsert pattern)
        existing_report = (
            db.query(InvestigationReport)
            .filter(InvestigationReport.analysis_id == analysis_id)
            .first()
        )

        # Derive (or re-derive) the risk result from features
        risk_result = calculate_risk_score(features)

        # Build indicator list for the report generator
        indicator_list = [
            {
                "indicator_type": ind.indicator_type,
                "severity": ind.severity.value if hasattr(ind.severity, "value") else ind.severity,
                "detail": ind.detail,
                "confidence": ind.confidence,
                "source_module": ind.source_module,
            }
            for ind in indicators
        ]

        # Generate the structured report
        report_data = generate_report(
            analysis_id=analysis_id,
            risk_result=risk_result,
            features=features,
        )

        if existing_report:
            # Update in place
            existing_report.verdict = Verdict(risk_result.verdict)
            existing_report.risk_score = risk_result.risk_score
            existing_report.report_data = report_data
            existing_report.top_contributors = risk_result.top_contributors
        else:
            report = InvestigationReport(
                analysis_id=analysis_id,
                verdict=Verdict(risk_result.verdict),
                risk_score=risk_result.risk_score,
                report_data=report_data,
                top_contributors=risk_result.top_contributors,
            )
            db.add(report)

        # Mark the job as complete
        job.status = AnalysisStatus.COMPLETE
        job.completed_at = datetime.utcnow()

        db.commit()

        logger.info(
            LogEvents.REPORT_GENERATED,
            task="generate_report_task",
            analysis_id=analysis_id,
            verdict=risk_result.verdict,
            risk_score=risk_result.risk_score,
        )

        return {
            "analysis_id": analysis_id,
            "verdict": risk_result.verdict,
            "risk_score": risk_result.risk_score,
        }

    except Exception as exc:
        db.rollback()
        logger.error(
            LogEvents.WORKER_TASK_FAILED,
            task="generate_report_task",
            analysis_id=analysis_id,
            error=str(exc),
        )
        raise self.retry(exc=exc)

    finally:
        db.close()
