# PhisMail — System Architecture

## Overview

PhisMail is a SOC-grade phishing investigation platform analyzing suspicious emails (.eml) and URLs through a modular, asynchronous pipeline producing structured investigation reports.

## Architecture Diagram

```
[Upload .eml / URL]
       ↓
[FastAPI Gateway] → [Validation + Dedup (SHA256)]
       ↓
[Redis Queue Dispatch]
       ↓
[Celery Worker Pipeline]
       ↓
┌──────────┬──────────────┬──────────────┐
│ Parse    │ Headers      │ URLs         │
│ Email    │ SPF/DKIM     │ Structural   │
│          │ DMARC        │ Obfuscation  │
└──────────┴──────────────┴──────────────┘
       ↓
┌──────────┬──────────────┬──────────────┐
│ NLP      │ Threat Intel │ Domain Intel │
│ Language │ OpenPhish    │ WHOIS + DNS  │
│ Detector │ PhishTank    │ Homograph    │
│          │ URLHaus      │              │
└──────────┴──────────────┴──────────────┘
       ↓
[Feature Aggregation (~80 features, 12 categories)]
       ↓
[Risk Scoring (weighted + severity model)]
       ↓
[Report Generation → PostgreSQL]
       ↓
[SOC Dashboard Display]
```

## Component Stack

| Component | Technology | Purpose |
|---|---|---|
| API Gateway | FastAPI + slowapi | Ingestion, validation, rate limiting |
| Task Queue | Redis | Message broker + cache |
| Workers | Celery | Distributed analysis pipeline |
| Database | PostgreSQL (SQLAlchemy) | Persistent storage |
| ML Engine | scikit-learn / XGBoost (pluggable) | Future trained classifier |
| NLP Engine | Regex-based keyword detection | Social engineering analysis |
| Frontend | Next.js + TailwindCSS v4 | SOC investigation dashboard |
| Reverse Proxy | NGINX | Routing + TLS termination |
| Containers | Docker Compose | Orchestration |

## Key Design Decisions

1. **Artifact Dedup** — SHA256 hash prevents re-analyzing identical emails/URLs
2. **Feature Store** — All features persisted per-analysis for ML retraining
3. **Severity Model** — 4-tier (CRITICAL/HIGH/MEDIUM/LOW) classification
4. **Async Pipeline** — Heavy analysis via Celery with 5 queue types
5. **SHAP Explainability** — Top-10 feature attributions per verdict
6. **IOC Export** — JSON, CSV, STIX2 formats for SOC integration
7. **Graceful Degradation** — Threat intel feeds fail independently
8. **Audit Trail** — Every pipeline event logged to AuditLog table
