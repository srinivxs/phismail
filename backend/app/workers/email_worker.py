"""
PhisMail — Email Analysis Worker
Celery tasks for email-specific pipeline steps.
"""

from app.core.celery_app import celery_app
from app.core.database import SessionLocal
from app.core.logging import get_logger, LogEvents
from app.models.models import (
    AnalysisJob, ParsedEmail,
)

logger = get_logger(__name__)


@celery_app.task(bind=True, max_retries=3, default_retry_delay=10, queue='email')
def parse_and_analyze_email(self, analysis_id: str) -> dict:
    """Parse an .eml file and run header analysis, persisting results to DB."""

    from app.services.email_parser.parser import parse_eml_file
    from app.services.header_analysis.header_analyzer import analyze_headers

    db = SessionLocal()

    try:
        logger.info(LogEvents.WORKER_TASK_STARTED, task="parse_and_analyze_email", analysis_id=analysis_id)

        job = db.query(AnalysisJob).filter(AnalysisJob.id == analysis_id).first()
        if not job:
            logger.error("analysis_job_not_found", analysis_id=analysis_id)
            return {"analysis_id": analysis_id, "error": "job_not_found"}

        # Step 1: Parse the .eml file
        parsed = parse_eml_file(job.artifact_location)

        parsed_email = ParsedEmail(
            analysis_id=analysis_id,
            sender=parsed.sender,
            reply_to=parsed.reply_to,
            return_path=parsed.return_path,
            subject=parsed.subject,
            body_text=parsed.body_text,
            body_html=parsed.body_html,
            headers=parsed.headers,
            attachments_meta=parsed.attachments,
            originating_ip=parsed.originating_ip,
        )
        db.add(parsed_email)

        # Step 2: Analyze headers
        header_result = analyze_headers(
            headers=parsed.headers,
            sender=parsed.sender,
            reply_to=parsed.reply_to,
            return_path=parsed.return_path,
            originating_ip=parsed.originating_ip,
        )

        parsed_email.spf_pass = header_result.spf_pass
        parsed_email.dkim_pass = header_result.dkim_pass
        parsed_email.dmarc_pass = header_result.dmarc_pass
        parsed_email.reply_to_mismatch = header_result.reply_to_mismatch
        parsed_email.return_path_mismatch = header_result.return_path_mismatch
        parsed_email.sender_domain_mismatch = header_result.sender_domain_mismatch

        db.commit()

        logger.info(
            LogEvents.WORKER_TASK_COMPLETED,
            task="parse_and_analyze_email",
            analysis_id=analysis_id,
            url_count=len(parsed.urls),
            has_attachments=len(parsed.attachments) > 0,
        )

        return {
            "analysis_id": analysis_id,
            "url_count": len(parsed.urls),
            "has_attachments": len(parsed.attachments) > 0,
        }

    except Exception as exc:
        db.rollback()
        logger.error(
            LogEvents.WORKER_TASK_FAILED,
            task="parse_and_analyze_email",
            analysis_id=analysis_id,
            error=str(exc),
        )
        raise self.retry(exc=exc)

    finally:
        db.close()
