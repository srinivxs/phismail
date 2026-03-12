"""
PhisMail — Celery Pipeline Orchestrator
Runs the full analysis pipeline as a chain of Celery tasks.
"""

from datetime import datetime
from sqlalchemy.orm import Session

from app.core.celery_app import celery_app
from app.core.database import SessionLocal
from app.core.logging import get_logger, LogEvents
from app.models.models import (
    AnalysisJob, AnalysisStatus, ArtifactType, ParsedEmail,
    ExtractedUrl, Indicator, DomainIntelligence, ThreatIntelHit,
    FeatureVector, InvestigationReport, AuditLog, Severity, Verdict,
)

logger = get_logger(__name__)


@celery_app.task(bind=True, max_retries=3, default_retry_delay=10)
def run_analysis_pipeline(self, analysis_id: str):
    """Main pipeline orchestrator — runs all analysis steps."""

    db = SessionLocal()

    try:
        job = db.query(AnalysisJob).filter(AnalysisJob.id == analysis_id).first()
        if not job:
            logger.error("analysis_job_not_found", analysis_id=analysis_id)
            return

        # Update status to processing
        job.status = AnalysisStatus.PROCESSING
        db.commit()
        _log_audit(db, "pipeline_started", analysis_id)

        logger.info(LogEvents.WORKER_TASK_STARTED, analysis_id=analysis_id)

        if job.artifact_type == ArtifactType.EMAIL:
            _process_email(db, job)
        elif job.artifact_type == ArtifactType.URL:
            _process_url(db, job)

        # Mark complete
        job.status = AnalysisStatus.COMPLETE
        job.completed_at = datetime.utcnow()
        db.commit()

        _log_audit(db, "pipeline_completed", analysis_id)
        logger.info(LogEvents.WORKER_TASK_COMPLETED, analysis_id=analysis_id)

    except Exception as exc:
        db.rollback()
        logger.error(LogEvents.WORKER_TASK_FAILED, analysis_id=analysis_id, error=str(exc))

        try:
            job = db.query(AnalysisJob).filter(AnalysisJob.id == analysis_id).first()
            if job:
                job.status = AnalysisStatus.FAILED
                job.error_message = str(exc)[:1000]
                db.commit()
            _log_audit(db, "pipeline_failed", analysis_id, detail=str(exc)[:500])
        except Exception:
            pass

        raise self.retry(exc=exc)

    finally:
        db.close()


def _process_email(db: Session, job: AnalysisJob):
    """Process an email artifact through the full pipeline."""

    from app.services.email_parser.parser import parse_eml_file
    from app.services.header_analysis.header_analyzer import analyze_headers
    from app.services.url_analysis.url_analyzer import analyze_url
    from app.services.domain_intelligence.whois_lookup import whois_lookup, dns_lookup
    from app.services.domain_intelligence.homograph_detector import detect_homograph
    from app.services.nlp_analysis.phishing_language_detector import analyze_phishing_language
    from app.services.attachment_analysis.attachment_risk_detector import analyze_attachments
    from app.services.feature_engineering.feature_builder import build_feature_vector
    from app.services.risk_scoring.rule_engine import calculate_risk_score
    from app.services.reporting.report_generator import generate_report

    analysis_id = job.id

    # Step 1: Parse email
    parsed = parse_eml_file(job.artifact_location)
    parsed_email = ParsedEmail(
        analysis_id=analysis_id,
        sender=parsed.sender,
        reply_to=parsed.reply_to,
        return_path=parsed.return_path,
        subject=parsed.subject,
        body_text=parsed.body_text,
        body_html=parsed.body_html,
        headers=parsed.headers,
        attachments_meta=parsed.attachments,
        originating_ip=parsed.originating_ip,
    )
    db.add(parsed_email)

    # Step 2: Header analysis
    header_result = analyze_headers(
        headers=parsed.headers,
        sender=parsed.sender,
        reply_to=parsed.reply_to,
        return_path=parsed.return_path,
        originating_ip=parsed.originating_ip,
    )
    parsed_email.spf_pass = header_result.spf_pass
    parsed_email.dkim_pass = header_result.dkim_pass
    parsed_email.dmarc_pass = header_result.dmarc_pass
    parsed_email.reply_to_mismatch = header_result.reply_to_mismatch
    parsed_email.return_path_mismatch = header_result.return_path_mismatch
    parsed_email.sender_domain_mismatch = header_result.sender_domain_mismatch

    # Step 3: URL analysis
    url_results = []
    for url_str in parsed.urls:
        url_analysis = analyze_url(url_str)
        url_results.append(url_analysis)

        extracted = ExtractedUrl(
            analysis_id=analysis_id,
            url=url_str,
            source="email_body",
            domain=url_analysis.domain,
            tld=url_analysis.tld,
            url_length=url_analysis.url_length,
            num_subdomains=url_analysis.num_subdomains,
            num_special_chars=url_analysis.num_special_chars,
            contains_ip=url_analysis.contains_ip,
            is_shortened=url_analysis.is_shortened,
            entropy_score=url_analysis.entropy_score,
            percent_encoding_count=url_analysis.percent_encoding_count,
            username_in_url=url_analysis.username_in_url,
        )
        db.add(extracted)

    # Step 4: Domain intelligence (first URL or sender domain)
    primary_domain = url_results[0].domain if url_results else None
    domain_whois = None
    domain_dns = None
    homograph_result = None

    if primary_domain:
        domain_whois = whois_lookup(primary_domain)
        domain_dns = dns_lookup(primary_domain)
        homograph_result = detect_homograph(primary_domain)

        domain_intel = DomainIntelligence(
            analysis_id=analysis_id,
            domain=primary_domain,
            registrar=domain_whois.registrar,
            registration_date=domain_whois.registration_date,
            expiry_date=domain_whois.expiry_date,
            domain_age_days=domain_whois.domain_age_days,
            nameservers=domain_whois.nameservers,
            dns_records={
                "a": domain_dns.a_records,
                "mx": domain_dns.mx_records,
                "txt": domain_dns.txt_records,
                "ns": domain_dns.ns_records,
            },
            is_homograph=homograph_result.is_homograph if homograph_result else False,
            brand_impersonation=homograph_result.matched_brand is not None if homograph_result else False,
            brand_keyword=homograph_result.matched_brand if homograph_result else None,
        )
        db.add(domain_intel)

    # Step 5: NLP analysis
    nlp_result = analyze_phishing_language(
        subject=parsed.subject,
        body_text=parsed.body_text,
        body_html=parsed.body_html,
    )

    # Step 6: Attachment analysis
    attachment_result = analyze_attachments(parsed.attachments)

    # Step 7: Feature aggregation
    features = build_feature_vector(
        header_result=header_result,
        url_results=url_results,
        domain_whois=domain_whois,
        domain_dns=domain_dns,
        nlp_result=nlp_result,
        attachment_result=attachment_result,
        homograph_result=homograph_result,
        email_body_text=parsed.body_text,
        email_body_html=parsed.body_html,
        email_urls=parsed.urls,
    )

    # Persist features to feature store
    for feat_name, feat_value in features.items():
        fv = FeatureVector(
            analysis_id=analysis_id,
            feature_name=feat_name,
            feature_value=feat_value,
            feature_category=_get_feature_category(feat_name),
        )
        db.add(fv)

    # Step 8: Risk scoring
    scoring_context = {
        "sender": parsed.sender,
        "reply_to": parsed.reply_to,
        "return_path": parsed.return_path,
        "primary_domain": url_results[0].domain if url_results else None,
        "domain_age_days": domain_whois.domain_age_days if domain_whois else None,
        "registrar": domain_whois.registrar if domain_whois else None,
        "registration_date": str(domain_whois.registration_date.date()) if domain_whois and domain_whois.registration_date else None,
        "brand_keyword": homograph_result.matched_brand if homograph_result else None,
        "nlp_patterns": nlp_result.detected_patterns,
        "urls": [r.url if hasattr(r, "url") else str(r) for r in url_results],
        "attachments": parsed.attachments or [],
        "display_name": header_result.display_name if header_result else None,
        "display_name_brand": header_result.display_name_brand if header_result else None,
    }
    risk_result = calculate_risk_score(features, context=scoring_context)

    # Save indicators
    for ind_data in risk_result.indicators:
        indicator = Indicator(
            analysis_id=analysis_id,
            indicator_type=ind_data["indicator_type"],
            severity=Severity(ind_data["severity"]),
            detail=ind_data.get("detail"),
            confidence=ind_data.get("confidence"),
            source_module=ind_data.get("source_module", "pipeline"),
        )
        db.add(indicator)

    # Step 9: Generate and persist report
    report_data = generate_report(
        analysis_id=analysis_id,
        risk_result=risk_result,
        features=features,
        parsed_email=parsed,
        url_results=url_results,
    )

    report = InvestigationReport(
        analysis_id=analysis_id,
        verdict=Verdict(risk_result.verdict),
        risk_score=risk_result.risk_score,
        report_data=report_data,
        top_contributors=risk_result.top_contributors,
    )
    db.add(report)
    db.commit()


def _process_url(db: Session, job: AnalysisJob):
    """Process a URL artifact through the pipeline."""

    from app.services.url_analysis.url_analyzer import analyze_url
    from app.services.domain_intelligence.whois_lookup import whois_lookup, dns_lookup
    from app.services.domain_intelligence.homograph_detector import detect_homograph
    from app.services.feature_engineering.feature_builder import build_feature_vector
    from app.services.risk_scoring.rule_engine import calculate_risk_score
    from app.services.reporting.report_generator import generate_report

    analysis_id = job.id
    url = job.submitted_url

    # URL analysis
    url_analysis = analyze_url(url)
    url_results = [url_analysis]

    extracted = ExtractedUrl(
        analysis_id=analysis_id,
        url=url,
        source="direct_submission",
        domain=url_analysis.domain,
        tld=url_analysis.tld,
        url_length=url_analysis.url_length,
        num_subdomains=url_analysis.num_subdomains,
        num_special_chars=url_analysis.num_special_chars,
        contains_ip=url_analysis.contains_ip,
        is_shortened=url_analysis.is_shortened,
        entropy_score=url_analysis.entropy_score,
        percent_encoding_count=url_analysis.percent_encoding_count,
        username_in_url=url_analysis.username_in_url,
    )
    db.add(extracted)

    # Domain intelligence
    domain_whois = None
    domain_dns = None
    homograph_result = None

    if url_analysis.domain:
        domain_whois = whois_lookup(url_analysis.domain)
        domain_dns = dns_lookup(url_analysis.domain)
        homograph_result = detect_homograph(url_analysis.domain)

        domain_intel = DomainIntelligence(
            analysis_id=analysis_id,
            domain=url_analysis.domain,
            registrar=domain_whois.registrar,
            registration_date=domain_whois.registration_date,
            expiry_date=domain_whois.expiry_date,
            domain_age_days=domain_whois.domain_age_days,
            nameservers=domain_whois.nameservers,
            dns_records={
                "a": domain_dns.a_records,
                "mx": domain_dns.mx_records,
                "txt": domain_dns.txt_records,
                "ns": domain_dns.ns_records,
            },
            is_homograph=homograph_result.is_homograph if homograph_result else False,
            brand_impersonation=homograph_result.matched_brand is not None if homograph_result else False,
            brand_keyword=homograph_result.matched_brand if homograph_result else None,
        )
        db.add(domain_intel)

    # Feature aggregation
    features = build_feature_vector(
        url_results=url_results,
        domain_whois=domain_whois,
        domain_dns=domain_dns,
        homograph_result=homograph_result,
    )

    # Persist features
    for feat_name, feat_value in features.items():
        fv = FeatureVector(
            analysis_id=analysis_id,
            feature_name=feat_name,
            feature_value=feat_value,
            feature_category=_get_feature_category(feat_name),
        )
        db.add(fv)

    # Risk scoring
    scoring_context = {
        "primary_domain": url_analysis.domain,
        "domain_age_days": domain_whois.domain_age_days if domain_whois else None,
        "registrar": domain_whois.registrar if domain_whois else None,
        "registration_date": str(domain_whois.registration_date.date()) if domain_whois and domain_whois.registration_date else None,
        "brand_keyword": homograph_result.matched_brand if homograph_result else None,
        "nlp_patterns": [],
        "urls": [url],
        "attachments": [],
    }
    risk_result = calculate_risk_score(features, context=scoring_context)

    # Save indicators
    for ind_data in risk_result.indicators:
        indicator = Indicator(
            analysis_id=analysis_id,
            indicator_type=ind_data["indicator_type"],
            severity=Severity(ind_data["severity"]),
            detail=ind_data.get("detail"),
            confidence=ind_data.get("confidence"),
            source_module=ind_data.get("source_module", "pipeline"),
        )
        db.add(indicator)

    # Report
    report_data = generate_report(
        analysis_id=analysis_id,
        risk_result=risk_result,
        features=features,
        url_results=url_results,
    )

    report = InvestigationReport(
        analysis_id=analysis_id,
        verdict=Verdict(risk_result.verdict),
        risk_score=risk_result.risk_score,
        report_data=report_data,
        top_contributors=risk_result.top_contributors,
    )
    db.add(report)
    db.commit()


def _get_feature_category(feature_name: str) -> str:
    """Map feature name to category."""

    categories = {
        "email_header": ["spf_pass", "dkim_pass", "dmarc_pass", "reply_to_mismatch",
                         "return_path_mismatch", "sender_domain_mismatch", "originating_ip_present",
                         "num_received_headers", "smtp_hops", "ip_private_network"],
        "url_structural": ["url_length", "num_dots", "num_subdomains", "num_hyphens",
                           "num_special_chars", "contains_ip_address", "contains_at_symbol",
                           "num_query_parameters", "url_entropy_score", "num_fragments",
                           "has_https", "url_shortened"],
        "url_obfuscation": ["percent_encoding_count", "hex_encoding_count", "double_slash_redirect",
                            "encoded_characters_ratio", "username_in_url", "mixed_case_domain",
                            "long_query_string"],
        "threat_intelligence": ["openphish_match", "phishtank_match", "urlhaus_match",
                                "domain_blacklisted", "ip_blacklisted", "threat_confidence_score"],
        "nlp": ["urgency_keyword_count", "credential_request_keywords",
                "financial_request_keywords", "security_alert_keywords",
                "threat_language_score", "sentiment_score", "imperative_language_score"],
        "brand_impersonation": ["brand_keyword_present", "brand_domain_similarity_score",
                                "brand_typosquat_distance", "brand_homograph_detected"],
        "attachment_risk": ["attachment_count", "has_executable_attachment",
                            "has_script_attachment", "has_macro_document",
                            "double_extension_detected", "archive_with_executable",
                            "mime_mismatch_detected"],
    }

    for category, features in categories.items():
        if feature_name in features:
            return category

    return "other"


def _log_audit(db: Session, event_type: str, analysis_id: str, detail: str = None):
    """Log an audit event."""
    audit = AuditLog(
        event_type=event_type,
        analysis_id=analysis_id,
        actor="pipeline",
        detail=detail,
    )
    db.add(audit)
    db.commit()
