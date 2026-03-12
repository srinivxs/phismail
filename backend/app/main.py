"""
PhisMail — FastAPI Application Factory
Main application with CORS, rate limiting, Prometheus metrics, and structured logging.
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from prometheus_client import (
    Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST,
)
from starlette.responses import Response

from app.core.config import get_settings
from app.core.logging import setup_logging, get_logger
from app.api.router import api_router

settings = get_settings()
logger = get_logger(__name__)

# =============================================================================
# Prometheus Metrics
# =============================================================================

REQUEST_COUNT = Counter(
    "phismail_api_request_count",
    "Total API requests",
    ["method", "endpoint", "status"],
)
REQUEST_LATENCY = Histogram(
    "phismail_api_request_latency_seconds",
    "API request latency",
    ["method", "endpoint"],
)
ANALYSIS_COUNT = Counter(
    "phismail_analysis_total",
    "Total analyses submitted",
    ["artifact_type"],
)
ACTIVE_ANALYSES = Gauge(
    "phismail_active_analyses",
    "Currently processing analyses",
)
ERROR_COUNT = Counter(
    "phismail_error_count",
    "Total errors",
    ["error_type"],
)

CELERY_QUEUE_LENGTH = Gauge(
    "phismail_celery_queue_length",
    "Celery queue depth",
    ["queue"],
)
CELERY_ACTIVE_WORKERS = Gauge(
    "phismail_celery_active_workers",
    "Active Celery workers",
)
CELERY_TASK_FAILURES = Counter(
    "phismail_celery_task_failures_total",
    "Celery task failures",
    ["task_name"],
)
CELERY_TASK_RUNTIME = Histogram(
    "phismail_celery_task_runtime_seconds",
    "Celery task execution time",
    ["task_name"],
)


def update_celery_metrics() -> None:
    """Refresh Celery queue depth and worker count in Prometheus gauges.

    Failures are silently swallowed so the /metrics endpoint never errors
    due to broker or Redis unavailability.
    """
    try:
        from app.core.celery_app import celery_app
        import redis

        # --- Active workers ---
        try:
            inspect = celery_app.control.inspect(timeout=1)
            active = inspect.active() or {}
            CELERY_ACTIVE_WORKERS.set(len(active))
        except Exception:
            CELERY_ACTIVE_WORKERS.set(0)

        # --- Queue depths ---
        queue_names = ["email", "url", "enrichment", "scoring", "reports"]
        try:
            r = redis.Redis.from_url(settings.celery_broker_url)
            for queue_name in queue_names:
                try:
                    length = r.llen(queue_name)
                    CELERY_QUEUE_LENGTH.labels(queue=queue_name).set(length)
                except Exception:
                    CELERY_QUEUE_LENGTH.labels(queue=queue_name).set(0)
        except Exception:
            for queue_name in queue_names:
                CELERY_QUEUE_LENGTH.labels(queue=queue_name).set(0)

    except Exception:
        pass


# =============================================================================
# Rate Limiter
# =============================================================================

limiter = Limiter(key_func=get_remote_address)


# =============================================================================
# Application Factory
# =============================================================================

def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""

    # Setup structured logging
    setup_logging()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="SOC-grade phishing investigation platform",
        docs_url="/docs" if settings.debug else None,
        redoc_url="/redoc" if settings.debug else None,
    )

    # Rate limiting
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Prometheus metrics middleware
    @app.middleware("http")
    async def metrics_middleware(request: Request, call_next):
        import time
        method = request.method
        path = request.url.path

        start = time.time()
        response = await call_next(request)
        duration = time.time() - start

        REQUEST_COUNT.labels(
            method=method,
            endpoint=path,
            status=response.status_code,
        ).inc()
        REQUEST_LATENCY.labels(
            method=method,
            endpoint=path,
        ).observe(duration)

        return response

    # Prometheus metrics endpoint
    @app.get("/metrics", include_in_schema=False)
    async def metrics():
        update_celery_metrics()
        return Response(
            content=generate_latest(),
            media_type=CONTENT_TYPE_LATEST,
        )

    # Include routes
    app.include_router(api_router)

    @app.on_event("startup")
    async def startup():
        logger.info("PhisMail API starting", version=settings.app_version)

    @app.on_event("shutdown")
    async def shutdown():
        logger.info("PhisMail API shutting down")

    return app


# Create the app instance
app = create_app()
