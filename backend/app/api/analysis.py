"""
PhisMail — Analysis API Routes
Endpoints for artifact submission, status checking, and report retrieval.
"""

import os
import uuid
from datetime import datetime
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import compute_sha256, compute_url_hash
from app.core.logging import get_logger, LogEvents
from app.models.models import AnalysisJob, AnalysisStatus, ArtifactType
from app.schemas.schemas import (
    UrlSubmissionRequest,
    AnalysisJobResponse,
    AnalysisStatusResponse,
    AnalysisListResponse,
    ArtifactTypeEnum,
    AnalysisStatusEnum,
)

logger = get_logger(__name__)
settings = get_settings()
router = APIRouter(prefix="/api/v1", tags=["analysis"])


@router.post("/analyze/email", response_model=AnalysisJobResponse, status_code=201)
async def analyze_email(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """Upload an .eml file for phishing analysis."""

    # Validate file size
    contents = await file.read()
    if len(contents) > settings.max_upload_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum size of {settings.max_upload_size_mb}MB",
        )

    # Validate file extension
    filename = file.filename or "unknown.eml"
    if not filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only .eml files are accepted",
        )

    # Compute artifact hash for dedup
    artifact_hash = compute_sha256(contents)

    # Check for existing completed analysis with same hash
    existing = db.query(AnalysisJob).filter(
        AnalysisJob.artifact_hash == artifact_hash,
        AnalysisJob.status == AnalysisStatus.COMPLETE,
    ).first()

    if existing:
        logger.info(
            LogEvents.CACHE_HIT,
            analysis_id=existing.id,
            artifact_hash=artifact_hash,
        )
        return AnalysisJobResponse(
            analysis_id=existing.id,
            artifact_type=ArtifactTypeEnum.EMAIL,
            status=AnalysisStatusEnum(existing.status.value),
            created_at=existing.created_at,
            message="Returning cached analysis result",
        )

    # Store the uploaded file
    analysis_id = str(uuid.uuid4())
    storage_dir = os.path.join(settings.storage_path, "emails")
    os.makedirs(storage_dir, exist_ok=True)
    file_path = os.path.join(storage_dir, f"{analysis_id}.eml")
    with open(file_path, "wb") as f:
        f.write(contents)

    # Create analysis job
    job = AnalysisJob(
        id=analysis_id,
        artifact_type=ArtifactType.EMAIL,
        artifact_hash=artifact_hash,
        artifact_location=file_path,
        original_filename=filename,
        status=AnalysisStatus.PENDING,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    logger.info(
        LogEvents.ANALYSIS_STARTED,
        analysis_id=analysis_id,
        artifact_type="email",
        filename=filename,
    )

    # Dispatch to Celery pipeline
    from app.workers.pipeline import run_analysis_pipeline
    run_analysis_pipeline.delay(analysis_id)

    return AnalysisJobResponse(
        analysis_id=analysis_id,
        artifact_type=ArtifactTypeEnum.EMAIL,
        status=AnalysisStatusEnum.PENDING,
        created_at=job.created_at,
        message="Email analysis job created",
    )


@router.post("/analyze/url", response_model=AnalysisJobResponse, status_code=201)
async def analyze_url(
    request: UrlSubmissionRequest,
    db: Session = Depends(get_db),
):
    """Submit a suspicious URL for phishing analysis."""

    url = request.url.strip()

    # Basic URL validation
    if not url.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL must start with http:// or https://",
        )

    # Compute URL hash for dedup
    artifact_hash = compute_url_hash(url)

    # Check for existing completed analysis
    existing = db.query(AnalysisJob).filter(
        AnalysisJob.artifact_hash == artifact_hash,
        AnalysisJob.status == AnalysisStatus.COMPLETE,
    ).first()

    if existing:
        logger.info(
            LogEvents.CACHE_HIT,
            analysis_id=existing.id,
            artifact_hash=artifact_hash,
        )
        return AnalysisJobResponse(
            analysis_id=existing.id,
            artifact_type=ArtifactTypeEnum.URL,
            status=AnalysisStatusEnum(existing.status.value),
            created_at=existing.created_at,
            message="Returning cached analysis result",
        )

    # Create analysis job
    analysis_id = str(uuid.uuid4())
    job = AnalysisJob(
        id=analysis_id,
        artifact_type=ArtifactType.URL,
        artifact_hash=artifact_hash,
        submitted_url=url,
        status=AnalysisStatus.PENDING,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    logger.info(
        LogEvents.ANALYSIS_STARTED,
        analysis_id=analysis_id,
        artifact_type="url",
        url=url,
    )

    # Dispatch to Celery pipeline
    from app.workers.pipeline import run_analysis_pipeline
    run_analysis_pipeline.delay(analysis_id)

    return AnalysisJobResponse(
        analysis_id=analysis_id,
        artifact_type=ArtifactTypeEnum.URL,
        status=AnalysisStatusEnum.PENDING,
        created_at=job.created_at,
        message="URL analysis job created",
    )


@router.get("/analysis/{analysis_id}", response_model=AnalysisStatusResponse)
async def get_analysis_status(
    analysis_id: str,
    db: Session = Depends(get_db),
):
    """Get the current status of an analysis job."""

    job = db.query(AnalysisJob).filter(AnalysisJob.id == analysis_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found")

    return AnalysisStatusResponse(
        analysis_id=job.id,
        artifact_type=ArtifactTypeEnum(job.artifact_type.value),
        status=AnalysisStatusEnum(job.status.value),
        created_at=job.created_at,
        updated_at=job.updated_at,
        completed_at=job.completed_at,
        error_message=job.error_message,
    )


@router.get("/analyses", response_model=AnalysisListResponse)
async def list_analyses(
    page: int = 1,
    per_page: int = 20,
    db: Session = Depends(get_db),
):
    """List recent analyses (paginated)."""

    per_page = min(per_page, 100)
    offset = (page - 1) * per_page

    total = db.query(AnalysisJob).count()
    jobs = (
        db.query(AnalysisJob)
        .order_by(AnalysisJob.created_at.desc())
        .offset(offset)
        .limit(per_page)
        .all()
    )

    return AnalysisListResponse(
        total=total,
        page=page,
        per_page=per_page,
        analyses=[
            AnalysisStatusResponse(
                analysis_id=j.id,
                artifact_type=ArtifactTypeEnum(j.artifact_type.value),
                status=AnalysisStatusEnum(j.status.value),
                created_at=j.created_at,
                updated_at=j.updated_at,
                completed_at=j.completed_at,
                error_message=j.error_message,
            )
            for j in jobs
        ],
    )
