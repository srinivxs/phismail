"""
PhisMail — Health & Metrics API Routes
System health checks and Prometheus metrics endpoint.
"""

import time
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.core.config import get_settings
from app.core.database import get_db
from app.schemas.schemas import HealthResponse

router = APIRouter(tags=["health"])
settings = get_settings()
_start_time = time.time()


@router.get("/health", response_model=HealthResponse)
async def health_check(db: Session = Depends(get_db)):
    """Aggregate system health check."""

    db_status = "unknown"
    redis_status = "unknown"

    # Check database
    try:
        db.execute(text("SELECT 1"))
        db_status = "healthy"
    except Exception:
        db_status = "unhealthy"

    # Check Redis
    try:
        import redis as redis_lib
        r = redis_lib.from_url(settings.redis_url)
        r.ping()
        redis_status = "healthy"
    except Exception:
        redis_status = "unhealthy"

    overall = "healthy" if db_status == "healthy" and redis_status == "healthy" else "degraded"

    return HealthResponse(
        status=overall,
        version=settings.app_version,
        database=db_status,
        redis=redis_status,
        uptime_seconds=round(time.time() - _start_time, 2),
    )


@router.get("/health/database")
async def database_health(db: Session = Depends(get_db)):
    """Database connectivity check."""
    try:
        db.execute(text("SELECT 1"))
        return {"status": "healthy", "message": "Database connection successful"}
    except Exception as e:
        return {"status": "unhealthy", "message": str(e)}


@router.get("/health/redis")
async def redis_health():
    """Redis connectivity check."""
    try:
        import redis as redis_lib
        r = redis_lib.from_url(settings.redis_url)
        info = r.info("server")
        return {
            "status": "healthy",
            "redis_version": info.get("redis_version", "unknown"),
            "connected_clients": r.info("clients").get("connected_clients", 0),
        }
    except Exception as e:
        return {"status": "unhealthy", "message": str(e)}
