"""
PhisMail — Scoring Worker
Feature aggregation and risk scoring tasks.
"""

from types import SimpleNamespace

from app.core.celery_app import celery_app
from app.core.database import SessionLocal
from app.core.logging import get_logger, LogEvents
from app.models.models import (
    AnalysisJob, ParsedEmail, ExtractedUrl, DomainIntelligence,
    ThreatIntelHit, FeatureVector, Indicator, Severity,
)
from app.services.feature_engineering.feature_builder import build_feature_vector
from app.services.risk_scoring.rule_engine import calculate_risk_score

logger = get_logger(__name__)


def _get_feature_category(feature_name: str) -> str:
    """Map feature name to category."""

    categories = {
        "email_header": [
            "spf_pass", "dkim_pass", "dmarc_pass", "reply_to_mismatch",
            "return_path_mismatch", "sender_domain_mismatch", "originating_ip_present",
            "num_received_headers", "smtp_hops", "ip_private_network",
        ],
        "url_structural": [
            "url_length", "num_dots", "num_subdomains", "num_hyphens",
            "num_special_chars", "contains_ip_address", "contains_at_symbol",
            "num_query_parameters", "url_entropy_score", "num_fragments",
            "has_https", "url_shortened",
        ],
        "url_obfuscation": [
            "percent_encoding_count", "hex_encoding_count", "double_slash_redirect",
            "encoded_characters_ratio", "username_in_url", "mixed_case_domain",
            "long_query_string",
        ],
        "threat_intelligence": [
            "openphish_match", "phishtank_match", "urlhaus_match",
            "domain_blacklisted", "ip_blacklisted", "threat_confidence_score",
        ],
        "nlp": [
            "urgency_keyword_count", "credential_request_keywords",
            "financial_request_keywords", "security_alert_keywords",
            "threat_language_score", "sentiment_score", "imperative_language_score",
        ],
        "brand_impersonation": [
            "brand_keyword_present", "brand_domain_similarity_score",
            "brand_typosquat_distance", "brand_homograph_detected",
        ],
        "attachment_risk": [
            "attachment_count", "has_executable_attachment",
            "has_script_attachment", "has_macro_document",
            "double_extension_detected", "archive_with_executable",
            "mime_mismatch_detected",
        ],
    }

    for category, features in categories.items():
        if feature_name in features:
            return category

    return "other"


@celery_app.task(bind=True, max_retries=2, default_retry_delay=5, queue='scoring')
def score_analysis(self, analysis_id: str) -> dict:
    """Aggregate features from DB and compute risk score, persisting results."""

    db = SessionLocal()

    try:
        logger.info(LogEvents.WORKER_TASK_STARTED, task="score_analysis", analysis_id=analysis_id)

        # Load all related records
        job = db.query(AnalysisJob).filter(AnalysisJob.id == analysis_id).first()
        if not job:
            logger.error("analysis_job_not_found", analysis_id=analysis_id)
            return {"analysis_id": analysis_id, "error": "job_not_found"}

        parsed_email = db.query(ParsedEmail).filter(ParsedEmail.analysis_id == analysis_id).first()
        extracted_urls = db.query(ExtractedUrl).filter(ExtractedUrl.analysis_id == analysis_id).all()
        domain_intel = db.query(DomainIntelligence).filter(DomainIntelligence.analysis_id == analysis_id).first()
        threat_hits = db.query(ThreatIntelHit).filter(ThreatIntelHit.analysis_id == analysis_id).all()

        # Reconstruct header_result namespace from ParsedEmail DB record
        header_result = None
        if parsed_email:
            header_result = SimpleNamespace(
                spf_pass=parsed_email.spf_pass,
                dkim_pass=parsed_email.dkim_pass,
                dmarc_pass=parsed_email.dmarc_pass,
                reply_to_mismatch=parsed_email.reply_to_mismatch,
                return_path_mismatch=parsed_email.return_path_mismatch,
                sender_domain_mismatch=parsed_email.sender_domain_mismatch,
                originating_ip=parsed_email.originating_ip,
            )

        # Reconstruct url_results namespace list from ExtractedUrl DB records
        url_results = [
            SimpleNamespace(
                url=u.url,
                domain=u.domain,
                tld=u.tld,
                url_length=u.url_length,
                num_subdomains=u.num_subdomains,
                num_special_chars=u.num_special_chars,
                contains_ip=u.contains_ip,
                is_shortened=u.is_shortened,
                entropy_score=u.entropy_score,
                percent_encoding_count=u.percent_encoding_count,
                username_in_url=u.username_in_url,
            )
            for u in extracted_urls
        ]

        # Reconstruct domain_whois namespace from DomainIntelligence DB record
        domain_whois = None
        domain_dns = None
        homograph_result = None
        if domain_intel:
            domain_whois = SimpleNamespace(
                registrar=domain_intel.registrar,
                registration_date=domain_intel.registration_date,
                expiry_date=domain_intel.expiry_date,
                domain_age_days=domain_intel.domain_age_days,
                nameservers=domain_intel.nameservers,
            )
            dns_data = domain_intel.dns_records or {}
            domain_dns = SimpleNamespace(
                a_records=dns_data.get("a", []),
                mx_records=dns_data.get("mx", []),
                txt_records=dns_data.get("txt", []),
                ns_records=dns_data.get("ns", []),
            )
            homograph_result = SimpleNamespace(
                is_homograph=domain_intel.is_homograph,
                matched_brand=domain_intel.brand_keyword,
            )

        # Reconstruct email body fields from ParsedEmail
        email_body_text = parsed_email.body_text if parsed_email else None
        email_body_html = parsed_email.body_html if parsed_email else None
        email_urls = [u.url for u in extracted_urls]

        # Build feature vector — pass only the arguments that are available
        build_kwargs = dict(
            url_results=url_results,
            domain_whois=domain_whois,
            domain_dns=domain_dns,
            homograph_result=homograph_result,
        )
        if header_result is not None:
            build_kwargs["header_result"] = header_result
        if email_body_text is not None:
            build_kwargs["email_body_text"] = email_body_text
        if email_body_html is not None:
            build_kwargs["email_body_html"] = email_body_html
        if email_urls:
            build_kwargs["email_urls"] = email_urls

        features = build_feature_vector(**build_kwargs)

        # Persist feature vectors
        for feat_name, feat_value in features.items():
            fv = FeatureVector(
                analysis_id=analysis_id,
                feature_name=feat_name,
                feature_value=feat_value,
                feature_category=_get_feature_category(feat_name),
            )
            db.add(fv)

        # Calculate risk score
        risk_result = calculate_risk_score(features)

        # Persist indicators
        for ind_data in risk_result.indicators:
            indicator = Indicator(
                analysis_id=analysis_id,
                indicator_type=ind_data["indicator_type"],
                severity=Severity(ind_data["severity"]),
                detail=ind_data.get("detail"),
                confidence=ind_data.get("confidence"),
                source_module=ind_data.get("source_module", "scoring_worker"),
            )
            db.add(indicator)

        db.commit()

        logger.info(
            LogEvents.WORKER_TASK_COMPLETED,
            task="score_analysis",
            analysis_id=analysis_id,
            verdict=risk_result.verdict,
            risk_score=risk_result.risk_score,
            indicator_count=len(risk_result.indicators),
        )

        return {
            "analysis_id": analysis_id,
            "verdict": risk_result.verdict,
            "risk_score": risk_result.risk_score,
            "indicator_count": len(risk_result.indicators),
        }

    except Exception as exc:
        db.rollback()
        logger.error(
            LogEvents.WORKER_TASK_FAILED,
            task="score_analysis",
            analysis_id=analysis_id,
            error=str(exc),
        )
        raise self.retry(exc=exc)

    finally:
        db.close()
