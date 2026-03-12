"""
PhisMail — Enrichment Worker
Domain intelligence + threat intelligence enrichment tasks.
"""

import asyncio

from app.core.celery_app import celery_app
from app.core.database import SessionLocal
from app.core.logging import get_logger, LogEvents
from app.models.models import DomainIntelligence, ThreatIntelHit

logger = get_logger(__name__)


@celery_app.task(bind=True, max_retries=3, default_retry_delay=10, queue='enrichment')
def enrich_domain(self, analysis_id: str, domain: str) -> dict:
    """Run WHOIS, DNS, and homograph detection for a domain and persist results."""

    from app.services.domain_intelligence.whois_lookup import whois_lookup, dns_lookup
    from app.services.domain_intelligence.homograph_detector import detect_homograph

    db = SessionLocal()

    try:
        logger.info(
            LogEvents.ENRICHMENT_STARTED,
            task="enrich_domain",
            analysis_id=analysis_id,
            domain=domain,
        )

        domain_whois = whois_lookup(domain)
        domain_dns = dns_lookup(domain)
        homograph_result = detect_homograph(domain)

        domain_intel = DomainIntelligence(
            analysis_id=analysis_id,
            domain=domain,
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
        db.commit()

        logger.info(
            LogEvents.ENRICHMENT_COMPLETED,
            task="enrich_domain",
            analysis_id=analysis_id,
            domain=domain,
            is_homograph=domain_intel.is_homograph,
            brand_impersonation=domain_intel.brand_impersonation,
        )

        return {
            "analysis_id": analysis_id,
            "domain": domain,
            "registrar": domain_whois.registrar,
            "domain_age_days": domain_whois.domain_age_days,
            "is_homograph": domain_intel.is_homograph,
            "brand_impersonation": domain_intel.brand_impersonation,
            "brand_keyword": domain_intel.brand_keyword,
        }

    except Exception as exc:
        db.rollback()
        logger.error(
            LogEvents.ENRICHMENT_FAILED,
            task="enrich_domain",
            analysis_id=analysis_id,
            domain=domain,
            error=str(exc),
        )
        raise self.retry(exc=exc)

    finally:
        db.close()


@celery_app.task(bind=True, max_retries=2, default_retry_delay=5, queue='enrichment')
def check_threat_intel(self, analysis_id: str, url: str) -> dict:
    """Check a URL against threat intelligence feeds and persist any hits."""

    from app.services.threat_intelligence.threat_intel_service import check_threat_intelligence

    db = SessionLocal()

    try:
        logger.info(
            LogEvents.ENRICHMENT_STARTED,
            task="check_threat_intel",
            analysis_id=analysis_id,
            url=url,
        )

        # Run the async threat intel check from the sync Celery context
        threat_result = asyncio.run(check_threat_intelligence(url))

        matched_sources = []

        if threat_result and threat_result.matches:
            for match in threat_result.matches:
                hit = ThreatIntelHit(
                    analysis_id=analysis_id,
                    source=match.source,
                    matched_url=url,
                    matched_domain=match.matched_domain if hasattr(match, "matched_domain") else None,
                    confidence_score=match.confidence_score if hasattr(match, "confidence_score") else None,
                    feed_data=match.feed_data if hasattr(match, "feed_data") else None,
                )
                db.add(hit)
                matched_sources.append(match.source)

            db.commit()

            logger.info(
                LogEvents.THREAT_INTEL_HIT,
                task="check_threat_intel",
                analysis_id=analysis_id,
                url=url,
                sources=matched_sources,
            )
        else:
            logger.info(
                LogEvents.ENRICHMENT_COMPLETED,
                task="check_threat_intel",
                analysis_id=analysis_id,
                url=url,
                matched=False,
            )

        return {
            "analysis_id": analysis_id,
            "url": url,
            "matched": len(matched_sources) > 0,
            "sources": matched_sources,
        }

    except Exception as exc:
        db.rollback()
        logger.error(
            LogEvents.ENRICHMENT_FAILED,
            task="check_threat_intel",
            analysis_id=analysis_id,
            url=url,
            error=str(exc),
        )
        raise self.retry(exc=exc)

    finally:
        db.close()
