"""
PhisMail — Celery Application Configuration
Configured with Redis broker, retry policies, and task routing.
"""

from celery import Celery
from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "phismail",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

celery_app.conf.update(
    # Serialization
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",

    # Timezone
    timezone="UTC",
    enable_utc=True,

    # Retry & reliability
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_reject_on_worker_lost=True,

    # Default retry policy (exponential backoff)
    task_default_retry_delay=5,
    task_max_retries=3,

    # Task routing
    task_routes={
        "app.workers.pipeline.*": {"queue": "email"},
        "app.workers.email_worker.*": {"queue": "email"},
        "app.workers.url_worker.*": {"queue": "url"},
        "app.workers.enrichment_worker.*": {"queue": "enrichment"},
        "app.workers.scoring_worker.*": {"queue": "scoring"},
        "app.workers.report_worker.*": {"queue": "reports"},
    },

    # Result expiration (24 hours)
    result_expires=86400,

    # Worker concurrency
    worker_concurrency=4,
)

# Explicitly import all task modules so they register with Celery
import app.workers.pipeline  # noqa: F401
import app.workers.email_worker  # noqa: F401
import app.workers.url_worker  # noqa: F401
import app.workers.enrichment_worker  # noqa: F401
import app.workers.scoring_worker  # noqa: F401
import app.workers.report_worker  # noqa: F401
