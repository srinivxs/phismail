"""
PhisMail — URL Analysis Worker
Celery tasks for URL analysis.
"""

from app.core.celery_app import celery_app
from app.core.database import SessionLocal
from app.core.logging import get_logger, LogEvents
from app.models.models import ExtractedUrl

logger = get_logger(__name__)


@celery_app.task(bind=True, max_retries=3, default_retry_delay=10, queue='url')
def analyze_urls_task(self, analysis_id: str, urls: list[str]) -> dict:
    """Analyze a list of URLs and persist ExtractedUrl records to DB."""

    from app.services.url_analysis.url_analyzer import analyze_url

    db = SessionLocal()

    try:
        logger.info(
            LogEvents.WORKER_TASK_STARTED,
            task="analyze_urls_task",
            analysis_id=analysis_id,
            url_count=len(urls),
        )

        domains = []

        for url_str in urls:
            url_analysis = analyze_url(url_str)

            extracted = ExtractedUrl(
                analysis_id=analysis_id,
                url=url_str,
                source="email_body",
                domain=url_analysis.domain,
                tld=url_analysis.tld,
                url_length=url_analysis.url_length,
                num_subdomains=url_analysis.num_subdomains,
                num_special_chars=url_analysis.num_special_chars,
                contains_ip=url_analysis.contains_ip,
                is_shortened=url_analysis.is_shortened,
                entropy_score=url_analysis.entropy_score,
                percent_encoding_count=url_analysis.percent_encoding_count,
                username_in_url=url_analysis.username_in_url,
            )
            db.add(extracted)

            if url_analysis.domain and url_analysis.domain not in domains:
                domains.append(url_analysis.domain)

        db.commit()

        logger.info(
            LogEvents.WORKER_TASK_COMPLETED,
            task="analyze_urls_task",
            analysis_id=analysis_id,
            urls_analyzed=len(urls),
            unique_domains=len(domains),
        )

        return {
            "analysis_id": analysis_id,
            "urls_analyzed": len(urls),
            "domains": domains,
        }

    except Exception as exc:
        db.rollback()
        logger.error(
            LogEvents.WORKER_TASK_FAILED,
            task="analyze_urls_task",
            analysis_id=analysis_id,
            error=str(exc),
        )
        raise self.retry(exc=exc)

    finally:
        db.close()
