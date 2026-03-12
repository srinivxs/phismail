"""
PhisMail — Structured Logging Helpers
Convenience wrappers for consistent, context-rich log events.
"""

from app.core.logging import get_logger, LogEvents

logger = get_logger(__name__)


def log_analysis_start(analysis_id: str, artifact_type: str) -> None:
    """Emit an info-level event when an analysis job begins."""
    logger.info(
        LogEvents.ANALYSIS_STARTED,
        analysis_id=analysis_id,
        artifact_type=artifact_type,
    )


def log_analysis_complete(
    analysis_id: str,
    verdict: str,
    risk_score: float,
    duration_ms: float,
) -> None:
    """Emit an info-level event when an analysis job completes successfully."""
    logger.info(
        LogEvents.ANALYSIS_COMPLETED,
        analysis_id=analysis_id,
        verdict=verdict,
        risk_score=risk_score,
        duration_ms=duration_ms,
    )


def log_analysis_failed(analysis_id: str, error: str, step: str) -> None:
    """Emit an error-level event when an analysis job fails."""
    logger.error(
        LogEvents.ANALYSIS_FAILED,
        analysis_id=analysis_id,
        error=error,
        step=step,
    )


def log_cache_hit(key: str, source: str) -> None:
    """Emit a debug-level event when a cache lookup succeeds."""
    logger.debug(
        LogEvents.CACHE_HIT,
        key=key,
        source=source,
    )


def log_cache_miss(key: str, source: str) -> None:
    """Emit a debug-level event when a cache lookup misses."""
    logger.debug(
        LogEvents.CACHE_MISS,
        key=key,
        source=source,
    )


def log_threat_intel_result(
    url: str,
    matched_sources: list[str],
    confidence: float,
) -> None:
    """Emit an info-level event with the result of a threat intelligence lookup."""
    logger.info(
        LogEvents.THREAT_INTEL_HIT,
        url=url,
        matched_sources=matched_sources,
        confidence=confidence,
    )


def log_pipeline_step(analysis_id: str, step: str, duration_ms: float) -> None:
    """Emit an info-level event recording the completion of a pipeline step."""
    logger.info(
        LogEvents.WORKER_TASK_COMPLETED,
        analysis_id=analysis_id,
        step=step,
        duration_ms=duration_ms,
    )
