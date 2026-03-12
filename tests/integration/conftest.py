"""Integration test configuration using FastAPI TestClient."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import patch, MagicMock

from app.main import create_app
from app.core.database import Base, get_db
from app.models.models import AnalysisJob, ArtifactType, AnalysisStatus


# =============================================================================
# Database Fixtures
# =============================================================================

@pytest.fixture(scope="session")
def engine():
    """Create a SQLite in-memory engine with all tables for the test session."""
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=test_engine)
    yield test_engine
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def db_session(engine):
    """Provide a fresh, rolled-back database session per test."""
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


# =============================================================================
# Application Fixtures
# =============================================================================

@pytest.fixture(scope="session")
def test_app():
    """Create a FastAPI app instance with DEBUG=True for integration tests."""
    with patch("app.core.config.get_settings") as mock_get_settings:
        mock_settings = MagicMock()
        mock_settings.app_name = "PhisMail-Test"
        mock_settings.app_version = "0.1.0-test"
        mock_settings.debug = True
        mock_settings.database_url = "sqlite:///:memory:"
        mock_settings.database_echo = False
        mock_settings.redis_url = "redis://localhost:6379/0"
        mock_settings.celery_broker_url = "redis://localhost:6379/1"
        mock_settings.celery_result_backend = "redis://localhost:6379/2"
        mock_settings.max_upload_size_mb = 5
        mock_settings.max_upload_size_bytes = 5 * 1024 * 1024
        mock_settings.storage_path = "/tmp/phismail-test"
        mock_settings.allowed_origins = "http://localhost:3000"
        mock_settings.allowed_origins_list = ["http://localhost:3000"]
        mock_settings.allowed_mime_types_list = ["message/rfc822"]
        mock_settings.rate_limit_per_hour = 1000
        mock_get_settings.return_value = mock_settings

        app = create_app()
        yield app


@pytest.fixture
def client(test_app, db_session):
    """Return a TestClient with the DB dependency overridden to use the test session."""

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    test_app.dependency_overrides[get_db] = override_get_db
    with TestClient(test_app) as c:
        yield c
    test_app.dependency_overrides.clear()


# =============================================================================
# Mock Fixtures
# =============================================================================

@pytest.fixture
def mock_celery():
    """Patch Celery task dispatch so tests do not need a running broker."""
    mock_result = MagicMock()
    mock_result.id = "test-task-id"

    with patch("app.workers.pipeline.run_analysis_pipeline.delay", return_value=mock_result) as mock_delay, \
         patch("app.core.celery_app.celery_app.send_task", return_value=mock_result) as mock_send:
        yield {
            "delay": mock_delay,
            "send_task": mock_send,
            "result": mock_result,
        }


# =============================================================================
# Data Fixtures
# =============================================================================

@pytest.fixture
def sample_analysis_job(db_session):
    """Create and persist a completed EMAIL AnalysisJob for use in tests."""
    job = AnalysisJob(
        artifact_type=ArtifactType.EMAIL,
        artifact_hash="deadbeef" * 8,
        original_filename="sample.eml",
        status=AnalysisStatus.COMPLETE,
    )
    db_session.add(job)
    db_session.commit()
    db_session.refresh(job)
    return job
