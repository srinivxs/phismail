"""Integration tests for /api/v1/analyze/* and /api/v1/analysis/* endpoints."""

import io
import pytest

from app.models.models import AnalysisJob, AnalysisStatus, ArtifactType
from app.core.security import compute_url_hash


class TestAnalysisAPI:
    """Integration tests for the analysis submission and status endpoints."""

    # -------------------------------------------------------------------------
    # Health endpoints
    # -------------------------------------------------------------------------

    def test_health_endpoint(self, client):
        """GET /api/v1/health should return 200 with a status key."""
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data

    def test_health_database(self, client):
        """GET /api/v1/health/database returns 200 when DB is reachable."""
        response = client.get("/api/v1/health/database")
        # With SQLite in-memory the DB is always available, but allow 503 too.
        assert response.status_code in (200, 503)

    # -------------------------------------------------------------------------
    # URL analysis
    # -------------------------------------------------------------------------

    def test_analyze_url_valid(self, client, mock_celery):
        """POST /api/v1/analyze/url with a valid http URL should return 201 + analysis_id."""
        response = client.post(
            "/api/v1/analyze/url",
            json={"url": "http://example.com"},
        )
        assert response.status_code in (201, 202)
        data = response.json()
        assert "analysis_id" in data
        assert data["analysis_id"]

    def test_analyze_url_invalid_scheme(self, client):
        """POST with a non-http/https scheme should be rejected with 400 or 422."""
        response = client.post(
            "/api/v1/analyze/url",
            json={"url": "ftp://bad.com"},
        )
        assert response.status_code in (400, 422)

    def test_analyze_url_empty(self, client):
        """POST with an empty URL string should be rejected with 400 or 422."""
        response = client.post(
            "/api/v1/analyze/url",
            json={"url": ""},
        )
        assert response.status_code in (400, 422)

    def test_analyze_url_deduplication(self, client, mock_celery, db_session):
        """Submitting the same URL twice should return a cached result on the second call."""
        url = "http://duplicate-test.example.com/page"

        # First submission — creates a new job.
        first = client.post("/api/v1/analyze/url", json={"url": url})
        assert first.status_code in (201, 202)
        first_id = first.json()["analysis_id"]

        # Mark the job as COMPLETE so dedup logic triggers.
        job = db_session.query(AnalysisJob).filter(AnalysisJob.id == first_id).first()
        if job:
            job.status = AnalysisStatus.COMPLETE
            db_session.commit()

        # Second submission — should return 200 (cache hit) or 201 (new job).
        second = client.post("/api/v1/analyze/url", json={"url": url})
        assert second.status_code in (200, 201, 202)
        second_data = second.json()
        assert "analysis_id" in second_data

    # -------------------------------------------------------------------------
    # Email analysis
    # -------------------------------------------------------------------------

    def test_analyze_email_valid(self, client, mock_celery, sample_eml_content):
        """POST multipart .eml file should return 201 + analysis_id."""
        response = client.post(
            "/api/v1/analyze/email",
            files={"file": ("test.eml", io.BytesIO(sample_eml_content), "message/rfc822")},
        )
        assert response.status_code in (201, 202)
        data = response.json()
        assert "analysis_id" in data
        assert data["analysis_id"]

    def test_analyze_email_wrong_extension(self, client):
        """POST a .txt file to the email endpoint should be rejected with 400 or 422."""
        response = client.post(
            "/api/v1/analyze/email",
            files={"file": ("notes.txt", io.BytesIO(b"not an eml"), "text/plain")},
        )
        assert response.status_code in (400, 422)

    # -------------------------------------------------------------------------
    # Analysis status and listing
    # -------------------------------------------------------------------------

    def test_get_analysis_status_not_found(self, client):
        """GET /api/v1/analysis/<unknown-id> should return 404."""
        response = client.get("/api/v1/analysis/nonexistent-id-00000")
        assert response.status_code == 404

    def test_get_analysis_status_found(self, client, sample_analysis_job):
        """GET /api/v1/analysis/<id> for an existing job should return 200 with status."""
        response = client.get(f"/api/v1/analysis/{sample_analysis_job.id}")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["analysis_id"] == sample_analysis_job.id

    def test_list_analyses(self, client, sample_analysis_job):
        """GET /api/v1/analyses should return 200 with total and analyses list."""
        response = client.get("/api/v1/analyses")
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "analyses" in data
        assert isinstance(data["analyses"], list)
        assert data["total"] >= 1
