"""
PhisMail — Pydantic Schemas
Request/response models for all API endpoints.
"""

from pydantic import BaseModel, Field, HttpUrl
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


# =============================================================================
# Enums
# =============================================================================

class ArtifactTypeEnum(str, Enum):
    EMAIL = "email"
    URL = "url"


class VerdictEnum(str, Enum):
    SAFE = "SAFE"
    MARKETING = "MARKETING"
    SUSPICIOUS = "SUSPICIOUS"
    PHISHING = "PHISHING"


class SeverityEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AnalysisStatusEnum(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETE = "complete"
    FAILED = "failed"


# =============================================================================
# Request Schemas
# =============================================================================

class UrlSubmissionRequest(BaseModel):
    """Request to analyze a suspicious URL."""
    url: str = Field(..., description="Suspicious URL to analyze", min_length=5, max_length=2048)


# =============================================================================
# Response Schemas
# =============================================================================

class AnalysisJobResponse(BaseModel):
    """Response after submitting an artifact for analysis."""
    analysis_id: str
    artifact_type: ArtifactTypeEnum
    status: AnalysisStatusEnum
    created_at: datetime
    message: str = "Analysis job created"

    model_config = {"from_attributes": True}


class AnalysisStatusResponse(BaseModel):
    """Current status of an analysis job."""
    analysis_id: str
    artifact_type: ArtifactTypeEnum
    status: AnalysisStatusEnum
    created_at: datetime
    updated_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None

    model_config = {"from_attributes": True}


class IndicatorResponse(BaseModel):
    """A single phishing indicator."""
    indicator_type: str
    severity: SeverityEnum
    detail: Optional[str] = None
    confidence: Optional[float] = None
    source_module: Optional[str] = None


class DomainIntelResponse(BaseModel):
    """Domain intelligence enrichment data."""
    domain: str
    registrar: Optional[str] = None
    registration_date: Optional[datetime] = None
    expiry_date: Optional[datetime] = None
    domain_age_days: Optional[int] = None
    nameservers: Optional[List[str]] = None
    dns_records: Optional[Dict[str, Any]] = None
    tld_risk_score: Optional[float] = None
    is_homograph: bool = False
    brand_impersonation: bool = False
    brand_keyword: Optional[str] = None


class UrlAnalysisResponse(BaseModel):
    """URL analysis result."""
    url: str
    domain: Optional[str] = None
    url_length: Optional[int] = None
    num_subdomains: Optional[int] = None
    contains_ip: bool = False
    is_shortened: bool = False
    entropy_score: Optional[float] = None
    redirect_count: int = 0
    redirect_chain: Optional[List[str]] = None
    final_destination: Optional[str] = None
    final_domain_mismatch: bool = False


class ThreatIntelHitResponse(BaseModel):
    """Threat intelligence match."""
    source: str
    matched_url: Optional[str] = None
    matched_domain: Optional[str] = None
    confidence_score: Optional[float] = None


class ExplainabilityResponse(BaseModel):
    """SHAP feature attribution for model explainability."""
    feature_name: str
    attribution_score: float
    direction: str  # "phishing" or "safe"


class InvestigationReportResponse(BaseModel):
    """Full investigation report."""
    analysis_id: str
    verdict: VerdictEnum
    risk_score: float
    phishing_probability: Optional[float] = None
    indicators: List[IndicatorResponse] = []
    extracted_urls: List[UrlAnalysisResponse] = []
    domain_intelligence: List[DomainIntelResponse] = []
    threat_intel_hits: List[ThreatIntelHitResponse] = []
    top_contributors: List[ExplainabilityResponse] = []
    created_at: Optional[datetime] = None


class AnalysisListResponse(BaseModel):
    """Paginated list of analyses."""
    total: int
    page: int
    per_page: int
    analyses: List[AnalysisStatusResponse]


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    version: str
    database: str = "unknown"
    redis: str = "unknown"
    uptime_seconds: Optional[float] = None


class ExportResponse(BaseModel):
    """IOC export metadata."""
    format: str
    analysis_id: str
    indicator_count: int
    export_data: Any


class AuditLogEntry(BaseModel):
    """Audit log entry."""
    event_type: str
    analysis_id: Optional[str] = None
    actor: Optional[str] = None
    detail: Optional[str] = None
    timestamp: datetime
