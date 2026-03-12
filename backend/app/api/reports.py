"""
PhisMail — Reports API Routes
Endpoints for retrieving investigation reports and exporting IOCs.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.models import (
    AnalysisJob, AnalysisStatus, InvestigationReport,
    Indicator, ExtractedUrl, DomainIntelligence, ThreatIntelHit,
)
from app.schemas.schemas import (
    InvestigationReportResponse,
    IndicatorResponse,
    UrlAnalysisResponse,
    DomainIntelResponse,
    ThreatIntelHitResponse,
    ExplainabilityResponse,
    ExportResponse,
    SeverityEnum,
)

router = APIRouter(prefix="/api/v1", tags=["reports"])


@router.get("/report/{analysis_id}", response_model=InvestigationReportResponse)
async def get_report(
    analysis_id: str,
    db: Session = Depends(get_db),
):
    """Get the full investigation report for a completed analysis."""

    job = db.query(AnalysisJob).filter(AnalysisJob.id == analysis_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found")

    if job.status != AnalysisStatus.COMPLETE:
        raise HTTPException(
            status_code=400,
            detail=f"Analysis is not complete. Current status: {job.status.value}",
        )

    report = db.query(InvestigationReport).filter(
        InvestigationReport.analysis_id == analysis_id
    ).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    # Fetch related data
    indicators = db.query(Indicator).filter(
        Indicator.analysis_id == analysis_id
    ).all()

    urls = db.query(ExtractedUrl).filter(
        ExtractedUrl.analysis_id == analysis_id
    ).all()

    domains = db.query(DomainIntelligence).filter(
        DomainIntelligence.analysis_id == analysis_id
    ).all()

    threat_hits = db.query(ThreatIntelHit).filter(
        ThreatIntelHit.analysis_id == analysis_id
    ).all()

    # Build explainability data
    top_contributors = []
    if report.top_contributors:
        for tc in report.top_contributors:
            top_contributors.append(ExplainabilityResponse(
                feature_name=tc.get("feature_name", ""),
                attribution_score=tc.get("attribution_score", 0.0),
                direction=tc.get("direction", "phishing"),
            ))

    return InvestigationReportResponse(
        analysis_id=analysis_id,
        verdict=report.verdict.value,
        risk_score=report.risk_score,
        phishing_probability=report.phishing_probability,
        indicators=[
            IndicatorResponse(
                indicator_type=ind.indicator_type,
                severity=SeverityEnum(ind.severity.value),
                detail=ind.detail,
                confidence=ind.confidence,
                source_module=ind.source_module,
            )
            for ind in indicators
        ],
        extracted_urls=[
            UrlAnalysisResponse(
                url=u.url,
                domain=u.domain,
                url_length=u.url_length,
                num_subdomains=u.num_subdomains,
                contains_ip=u.contains_ip,
                is_shortened=u.is_shortened,
                entropy_score=u.entropy_score,
                redirect_count=u.redirect_count,
                redirect_chain=u.redirect_chain,
                final_destination=u.final_destination,
                final_domain_mismatch=u.final_domain_mismatch,
            )
            for u in urls
        ],
        domain_intelligence=[
            DomainIntelResponse(
                domain=d.domain,
                registrar=d.registrar,
                registration_date=d.registration_date,
                expiry_date=d.expiry_date,
                domain_age_days=d.domain_age_days,
                nameservers=d.nameservers,
                dns_records=d.dns_records,
                tld_risk_score=d.tld_risk_score,
                is_homograph=d.is_homograph,
                brand_impersonation=d.brand_impersonation,
                brand_keyword=d.brand_keyword,
            )
            for d in domains
        ],
        threat_intel_hits=[
            ThreatIntelHitResponse(
                source=t.source,
                matched_url=t.matched_url,
                matched_domain=t.matched_domain,
                confidence_score=t.confidence_score,
            )
            for t in threat_hits
        ],
        top_contributors=top_contributors,
        created_at=report.created_at,
    )


@router.get("/report/{analysis_id}/export")
async def export_report(
    analysis_id: str,
    format: str = Query("json", regex="^(json|csv|stix2)$"),
    db: Session = Depends(get_db),
):
    """Export investigation indicators in JSON, CSV, or STIX2 format."""

    from app.services.reporting.ioc_exporter import export_iocs

    job = db.query(AnalysisJob).filter(AnalysisJob.id == analysis_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found")

    if job.status != AnalysisStatus.COMPLETE:
        raise HTTPException(
            status_code=400,
            detail=f"Analysis is not complete. Current status: {job.status.value}",
        )

    indicators = db.query(Indicator).filter(
        Indicator.analysis_id == analysis_id
    ).all()

    urls = db.query(ExtractedUrl).filter(
        ExtractedUrl.analysis_id == analysis_id
    ).all()

    export_data = export_iocs(
        analysis_id=analysis_id,
        indicators=indicators,
        urls=urls,
        export_format=format,
    )

    return ExportResponse(
        format=format,
        analysis_id=analysis_id,
        indicator_count=len(indicators),
        export_data=export_data,
    )
