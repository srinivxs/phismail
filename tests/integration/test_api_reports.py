"""Integration tests for /api/v1/report/* endpoints."""

import uuid
import pytest

from app.models.models import (
    AnalysisJob,
    AnalysisStatus,
    ArtifactType,
    InvestigationReport,
    Indicator,
    Severity,
    Verdict,
)


# =============================================================================
# Local fixtures
# =============================================================================

@pytest.fixture
def complete_analysis(db_session):
    """
    Create a fully-populated analysis: AnalysisJob (COMPLETE) + InvestigationReport
    + two Indicator records (HIGH and CRITICAL severity).
    """
    job = AnalysisJob(
        artifact_type=ArtifactType.EMAIL,
        artifact_hash="cafebabe" * 8,
        original_filename="phish.eml",
        status=AnalysisStatus.COMPLETE,
    )
    db_session.add(job)
    db_session.flush()  # Populate job.id without full commit

    report = InvestigationReport(
        analysis_id=job.id,
        verdict=Verdict.PHISHING,
        risk_score=85.0,
        phishing_probability=0.92,
        report_data={
            "summary": "High-confidence phishing detected",
            "features": {"openphish_match": 1.0, "reply_to_mismatch": 1.0},
        },
        top_contributors=[
            {
                "feature_name": "openphish_match",
                "attribution_score": 30.0,
                "direction": "phishing",
            },
            {
                "feature_name": "reply_to_mismatch",
                "attribution_score": 15.0,
                "direction": "phishing",
            },
        ],
    )
    db_session.add(report)

    indicator_high = Indicator(
        analysis_id=job.id,
        indicator_type="reply_to_mismatch",
        severity=Severity.HIGH,
        detail="Reply-To domain differs from From domain",
        confidence=0.9,
        source_module="header_analyzer",
    )
    indicator_critical = Indicator(
        analysis_id=job.id,
        indicator_type="openphish_match",
        severity=Severity.CRITICAL,
        detail="URL matched OpenPhish feed",
        confidence=1.0,
        source_module="threat_intel",
    )
    db_session.add(indicator_high)
    db_session.add(indicator_critical)
    db_session.commit()
    db_session.refresh(job)
    return job


# =============================================================================
# Test class
# =============================================================================

class TestReportsAPI:
    """Integration tests for investigation report retrieval and export."""

    # -------------------------------------------------------------------------
    # GET /api/v1/report/{analysis_id}
    # -------------------------------------------------------------------------

    def test_get_report_not_found(self, client):
        """GET /api/v1/report/<unknown-id> should return 404."""
        response = client.get("/api/v1/report/nonexistent-report-id-00000")
        assert response.status_code == 404

    def test_get_report_pending(self, client, db_session):
        """GET /api/v1/report/<id> for a PENDING job should return 400 (not complete)."""
        job = AnalysisJob(
            artifact_type=ArtifactType.URL,
            artifact_hash="00" * 32,
            submitted_url="http://pending.example.com",
            status=AnalysisStatus.PENDING,
        )
        db_session.add(job)
        db_session.commit()
        db_session.refresh(job)

        response = client.get(f"/api/v1/report/{job.id}")
        assert response.status_code in (400, 404)

    def test_get_report_complete(self, client, complete_analysis):
        """GET /api/v1/report/<id> for a complete job should return 200 with verdict and risk_score."""
        response = client.get(f"/api/v1/report/{complete_analysis.id}")
        assert response.status_code == 200
        data = response.json()
        assert data["verdict"] == "PHISHING"
        assert data["risk_score"] == 85.0
        assert "indicators" in data
        assert isinstance(data["indicators"], list)
        assert len(data["indicators"]) == 2

    # -------------------------------------------------------------------------
    # GET /api/v1/report/{analysis_id}/export
    # -------------------------------------------------------------------------

    def test_export_report_json(self, client, complete_analysis):
        """Export in JSON format should return 200 with JSON content."""
        response = client.get(
            f"/api/v1/report/{complete_analysis.id}/export",
            params={"format": "json"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["format"] == "json"
        assert data["analysis_id"] == complete_analysis.id

    def test_export_report_csv(self, client, complete_analysis):
        """Export in CSV format should return 200."""
        response = client.get(
            f"/api/v1/report/{complete_analysis.id}/export",
            params={"format": "csv"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["format"] == "csv"

    def test_export_report_stix2(self, client, complete_analysis):
        """Export in STIX2 format should return 200 with a STIX2 bundle."""
        response = client.get(
            f"/api/v1/report/{complete_analysis.id}/export",
            params={"format": "stix2"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["format"] == "stix2"
        assert data["analysis_id"] == complete_analysis.id
