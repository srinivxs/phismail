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

    # Task routing — all analysis goes through the monolithic pipeline task
    task_routes={
        "app.workers.pipeline.*": {"queue": "email"},
    },

    # Result expiration (24 hours)
    result_expires=86400,

    # Worker concurrency
    worker_concurrency=4,
)

# Import task modules so they register with Celery
import app.workers.pipeline  # noqa: F401
