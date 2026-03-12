"""
PhisMail — IOC Exporter
Export investigation indicators in JSON, CSV, or STIX2 formats.
"""

import json
import csv
import io
from typing import List, Any, Dict
from datetime import datetime

from app.core.logging import get_logger

logger = get_logger(__name__)


def export_iocs(
    analysis_id: str,
    indicators: List[Any],
    urls: List[Any],
    export_format: str = "json",
) -> Any:
    """Export IOCs in the specified format."""

    if export_format == "json":
        return _export_json(analysis_id, indicators, urls)
    elif export_format == "csv":
        return _export_csv(analysis_id, indicators, urls)
    elif export_format == "stix2":
        return _export_stix2(analysis_id, indicators, urls)
    else:
        return _export_json(analysis_id, indicators, urls)


def _export_json(analysis_id: str, indicators: List, urls: List) -> Dict:
    """Export as structured JSON."""

    return {
        "analysis_id": analysis_id,
        "exported_at": datetime.utcnow().isoformat(),
        "indicators": [
            {
                "type": ind.indicator_type,
                "severity": ind.severity.value if hasattr(ind.severity, "value") else ind.severity,
                "detail": ind.detail,
            }
            for ind in indicators
        ],
        "urls": [
            {
                "url": u.url,
                "domain": u.domain,
                "final_destination": u.final_destination,
            }
            for u in urls
        ],
    }


def _export_csv(analysis_id: str, indicators: List, urls: List) -> str:
    """Export as CSV string."""

    output = io.StringIO()
    writer = csv.writer(output)

    # Headers
    writer.writerow(["type", "value", "severity", "detail", "analysis_id"])

    # Indicators
    for ind in indicators:
        severity = ind.severity.value if hasattr(ind.severity, "value") else ind.severity
        writer.writerow([
            ind.indicator_type,
            "",
            severity,
            ind.detail or "",
            analysis_id,
        ])

    # URLs
    for u in urls:
        writer.writerow([
            "url",
            u.url,
            "INFO",
            f"domain: {u.domain}",
            analysis_id,
        ])

    return output.getvalue()


def _export_stix2(analysis_id: str, indicators: List, urls: List) -> Dict:
    """Export as STIX2 bundle (simplified)."""

    objects = []

    # Identity for the tool
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": f"identity--phismail-{analysis_id[:8]}",
        "created": datetime.utcnow().isoformat() + "Z",
        "modified": datetime.utcnow().isoformat() + "Z",
        "name": "PhisMail Analysis Platform",
        "identity_class": "system",
    }
    objects.append(identity)

    # Indicators
    for ind in indicators:
        severity = ind.severity.value if hasattr(ind.severity, "value") else ind.severity
        stix_indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{ind.id}" if hasattr(ind, "id") else f"indicator--{analysis_id[:8]}",
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": ind.indicator_type,
            "description": ind.detail or "",
            "indicator_types": ["malicious-activity"],
            "pattern_type": "stix",
            "pattern": f"[email-message:subject = '{ind.indicator_type}']",
            "valid_from": datetime.utcnow().isoformat() + "Z",
            "confidence": int((ind.confidence or 0.5) * 100),
            "labels": [severity.lower()],
        }
        objects.append(stix_indicator)

    # URLs as observables
    for u in urls:
        observable = {
            "type": "url",
            "spec_version": "2.1",
            "id": f"url--{u.id}" if hasattr(u, "id") else f"url--{analysis_id[:8]}",
            "value": u.url,
        }
        objects.append(observable)

    return {
        "type": "bundle",
        "id": f"bundle--{analysis_id}",
        "objects": objects,
    }
