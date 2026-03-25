"""
PhisMail — Database Models
All SQLAlchemy models for the phishing analysis pipeline.
"""

import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, Text, DateTime, JSON,
    ForeignKey, Enum as SQLEnum, Index,
)
from sqlalchemy.orm import relationship
from app.core.database import Base
import enum


# =============================================================================
# Enums
# =============================================================================

class AnalysisStatus(str, enum.Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETE = "complete"
    FAILED = "failed"


class ArtifactType(str, enum.Enum):
    EMAIL = "email"
    URL = "url"


class Verdict(str, enum.Enum):
    SAFE = "SAFE"
    MARKETING = "MARKETING"
    SUSPICIOUS = "SUSPICIOUS"
    PHISHING = "PHISHING"


class Severity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


def generate_uuid() -> str:
    return str(uuid.uuid4())


# =============================================================================
# Analysis Job
# =============================================================================

class AnalysisJob(Base):
    """Tracks the state of an analysis submission."""
    __tablename__ = "analysis_jobs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    artifact_type = Column(SQLEnum(ArtifactType), nullable=False)
    artifact_hash = Column(String(64), nullable=False, index=True)
    artifact_location = Column(String(512), nullable=True)
    original_filename = Column(String(256), nullable=True)
    submitted_url = Column(Text, nullable=True)
    status = Column(
        SQLEnum(AnalysisStatus),
        default=AnalysisStatus.PENDING,
        nullable=False,
        index=True,
    )
    error_message = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    parsed_email = relationship("ParsedEmail", back_populates="analysis_job", uselist=False)
    extracted_urls = relationship("ExtractedUrl", back_populates="analysis_job")
    indicators = relationship("Indicator", back_populates="analysis_job")
    domain_intel = relationship("DomainIntelligence", back_populates="analysis_job")
    threat_hits = relationship("ThreatIntelHit", back_populates="analysis_job")
    feature_vectors = relationship("FeatureVector", back_populates="analysis_job")
    report = relationship("InvestigationReport", back_populates="analysis_job", uselist=False)
    ml_predictions = relationship("MLPrediction", back_populates="analysis_job")

    __table_args__ = (
        Index("ix_artifact_hash_status", "artifact_hash", "status"),
    )


# =============================================================================
# Parsed Email
# =============================================================================

class ParsedEmail(Base):
    """Extracted components from a parsed .eml file."""
    __tablename__ = "parsed_emails"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    analysis_id = Column(String(36), ForeignKey("analysis_jobs.id"), nullable=False)

    sender = Column(String(512), nullable=True)
    reply_to = Column(String(512), nullable=True)
    return_path = Column(String(512), nullable=True)
    subject = Column(Text, nullable=True)
    body_text = Column(Text, nullable=True)
    body_html = Column(Text, nullable=True)
    headers = Column(JSON, nullable=True)
    attachments_meta = Column(JSON, nullable=True)

    # Email infrastructure intelligence
    originating_ip = Column(String(45), nullable=True)
    asn_number = Column(String(20), nullable=True)
    asn_org = Column(String(256), nullable=True)
    geo_country = Column(String(100), nullable=True)

    # Authentication results
    spf_pass = Column(Boolean, nullable=True)
    dkim_pass = Column(Boolean, nullable=True)
    dmarc_pass = Column(Boolean, nullable=True)
    reply_to_mismatch = Column(Boolean, default=False)
    return_path_mismatch = Column(Boolean, default=False)
    sender_domain_mismatch = Column(Boolean, default=False)

    created_at = Column(DateTime, default=datetime.utcnow)

    analysis_job = relationship("AnalysisJob", back_populates="parsed_email")


# =============================================================================
# Extracted URL
# =============================================================================

class ExtractedUrl(Base):
    """URLs found in analyzed artifacts."""
    __tablename__ = "extracted_urls"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    analysis_id = Column(String(36), ForeignKey("analysis_jobs.id"), nullable=False)

    url = Column(Text, nullable=False)
    source = Column(String(50), nullable=True)  # body_html, body_text, attachment
    domain = Column(String(256), nullable=True)
    tld = Column(String(20), nullable=True)

    # Structural analysis
    url_length = Column(Integer, nullable=True)
    num_subdomains = Column(Integer, nullable=True)
    num_special_chars = Column(Integer, nullable=True)
    contains_ip = Column(Boolean, default=False)
    is_shortened = Column(Boolean, default=False)
    entropy_score = Column(Float, nullable=True)

    # Redirect chain
    redirect_count = Column(Integer, default=0)
    redirect_chain = Column(JSON, nullable=True)
    final_destination = Column(Text, nullable=True)
    final_domain_mismatch = Column(Boolean, default=False)

    # Obfuscation
    percent_encoding_count = Column(Integer, default=0)
    username_in_url = Column(Boolean, default=False)

    created_at = Column(DateTime, default=datetime.utcnow)

    analysis_job = relationship("AnalysisJob", back_populates="extracted_urls")


# =============================================================================
# Indicator
# =============================================================================

class Indicator(Base):
    """Phishing indicators detected during analysis."""
    __tablename__ = "indicators"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    analysis_id = Column(String(36), ForeignKey("analysis_jobs.id"), nullable=False)

    indicator_type = Column(String(100), nullable=False)
    severity = Column(SQLEnum(Severity), nullable=False)
    detail = Column(Text, nullable=True)
    confidence = Column(Float, nullable=True)
    source_module = Column(String(100), nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    analysis_job = relationship("AnalysisJob", back_populates="indicators")


# =============================================================================
# Domain Intelligence
# =============================================================================

class DomainIntelligence(Base):
    """WHOIS and DNS enrichment data for analyzed domains."""
    __tablename__ = "domain_intelligence"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    analysis_id = Column(String(36), ForeignKey("analysis_jobs.id"), nullable=False)

    domain = Column(String(256), nullable=False, index=True)
    registrar = Column(String(256), nullable=True)
    registration_date = Column(DateTime, nullable=True)
    expiry_date = Column(DateTime, nullable=True)
    domain_age_days = Column(Integer, nullable=True)
    nameservers = Column(JSON, nullable=True)
    dns_records = Column(JSON, nullable=True)

    # Reputation signals
    tld_risk_score = Column(Float, nullable=True)
    is_homograph = Column(Boolean, default=False)
    brand_impersonation = Column(Boolean, default=False)
    brand_keyword = Column(String(100), nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    analysis_job = relationship("AnalysisJob", back_populates="domain_intel")


# =============================================================================
# Threat Intelligence Hit
# =============================================================================

class ThreatIntelHit(Base):
    """Matches from external threat intelligence feeds."""
    __tablename__ = "threat_intel_hits"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    analysis_id = Column(String(36), ForeignKey("analysis_jobs.id"), nullable=False)

    source = Column(String(50), nullable=False)  # openphish, phishtank, urlhaus
    matched_url = Column(Text, nullable=True)
    matched_domain = Column(String(256), nullable=True)
    confidence_score = Column(Float, nullable=True)
    feed_data = Column(JSON, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    analysis_job = relationship("AnalysisJob", back_populates="threat_hits")


# =============================================================================
# Feature Vector (ML Feature Store)
# =============================================================================

class FeatureVector(Base):
    """ML feature store — stores individual features per analysis."""
    __tablename__ = "feature_vectors"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    analysis_id = Column(String(36), ForeignKey("analysis_jobs.id"), nullable=False)

    feature_name = Column(String(100), nullable=False)
    feature_value = Column(Float, nullable=False)
    feature_category = Column(String(50), nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    analysis_job = relationship("AnalysisJob", back_populates="feature_vectors")

    __table_args__ = (
        Index("ix_feature_analysis", "analysis_id", "feature_name"),
    )


# =============================================================================
# Investigation Report
# =============================================================================

class InvestigationReport(Base):
    """Final investigation report with verdict and risk score."""
    __tablename__ = "investigation_reports"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    analysis_id = Column(String(36), ForeignKey("analysis_jobs.id"), nullable=False, unique=True)

    verdict = Column(SQLEnum(Verdict), nullable=False)
    risk_score = Column(Float, nullable=False)
    phishing_probability = Column(Float, nullable=True)
    report_data = Column(JSON, nullable=True)  # Full structured report

    # SHAP explainability
    top_contributors = Column(JSON, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    analysis_job = relationship("AnalysisJob", back_populates="report")


# =============================================================================
# Audit Log
# =============================================================================

class AuditLog(Base):
    """Forensic audit trail for all pipeline events."""
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    event_type = Column(String(100), nullable=False, index=True)
    analysis_id = Column(String(36), nullable=True, index=True)
    actor = Column(String(100), nullable=True)
    detail = Column(Text, nullable=True)
    metadata_json = Column(JSON, nullable=True)

    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)


# =============================================================================
# ML Model Registry
# =============================================================================

class MLModel(Base):
    """Version tracking for trained ML models."""
    __tablename__ = "ml_models"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    model_name = Column(String(100), nullable=False)
    model_version = Column(String(20), nullable=False)
    model_path = Column(String(512), nullable=True)
    training_date = Column(DateTime, nullable=True)
    training_dataset = Column(String(256), nullable=True)
    accuracy_score = Column(Float, nullable=True)
    f1_score = Column(Float, nullable=True)
    feature_count = Column(Integer, nullable=True)
    is_active = Column(Boolean, default=False)
    metadata_json = Column(JSON, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)


# =============================================================================
# ML Prediction
# =============================================================================

class MLPrediction(Base):
    """ML model predictions for each analysis."""
    __tablename__ = "ml_predictions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    analysis_id = Column(String(36), ForeignKey("analysis_jobs.id", ondelete="CASCADE"), nullable=False)

    prediction = Column(String(20), nullable=False)  # SAFE, SUSPICIOUS, PHISHING
    confidence = Column(Float, nullable=False)
    phishing_probability = Column(Float, nullable=False)
    legitimate_probability = Column(Float, nullable=False)
    model_version = Column(String(50), nullable=True)
    reasoning = Column(Text, nullable=True)
    stage = Column(String(50), nullable=True)  # whitelist, blacklist, auth_rules, ml_ensemble
    features_json = Column(JSON, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    analysis_job = relationship("AnalysisJob", back_populates="ml_predictions")
    feedback = relationship("MLFeedback", back_populates="prediction", uselist=False)

    __table_args__ = (
        Index("ix_ml_predictions_analysis", "analysis_id"),
    )


# =============================================================================
# ML Feedback
# =============================================================================

class MLFeedback(Base):
    """User feedback on ML predictions for continuous improvement."""
    __tablename__ = "ml_feedback"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    prediction_id = Column(String(36), ForeignKey("ml_predictions.id"), nullable=False)

    user_label = Column(String(20), nullable=False)  # PHISHING or LEGITIMATE
    was_correct = Column(Boolean, nullable=True)
    feedback_notes = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    prediction = relationship("MLPrediction", back_populates="feedback")


# =============================================================================
# Domain Whitelist
# =============================================================================

class DomainWhitelist(Base):
    """Trusted domains (manual or auto-learned from feedback)."""
    __tablename__ = "domain_whitelist"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    domain = Column(String(255), unique=True, nullable=False, index=True)
    confidence_score = Column(Float, default=1.0)
    added_by = Column(String(50), nullable=True)  # 'manual' or 'auto'
    confirmation_count = Column(Integer, default=1)
    last_seen = Column(DateTime, default=datetime.utcnow)

    created_at = Column(DateTime, default=datetime.utcnow)


# =============================================================================
# Domain Blacklist
# =============================================================================

class DomainBlacklist(Base):
    """Known malicious domains."""
    __tablename__ = "domain_blacklist"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    domain = Column(String(255), unique=True, nullable=False, index=True)
    threat_level = Column(String(20), nullable=True)  # HIGH, MEDIUM, LOW
    added_by = Column(String(50), nullable=True)
    report_count = Column(Integer, default=1)
    last_seen = Column(DateTime, default=datetime.utcnow)

    created_at = Column(DateTime, default=datetime.utcnow)


# =============================================================================
# User (Authentication)
# =============================================================================

class AuthProvider(str, enum.Enum):
    LOCAL = "local"
    GOOGLE = "google"


class User(Base):
    """Application user for authentication."""
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email = Column(String(320), unique=True, nullable=False, index=True)
    display_name = Column(String(100), nullable=True)
    hashed_password = Column(String(256), nullable=True)  # null for OAuth-only users
    auth_provider = Column(SQLEnum(AuthProvider), default=AuthProvider.LOCAL, nullable=False)
    google_sub = Column(String(256), nullable=True, unique=True)  # Google subject ID
    avatar_url = Column(String(512), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login_at = Column(DateTime, nullable=True)
