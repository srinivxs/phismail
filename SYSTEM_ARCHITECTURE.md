# PhisMail — System Architecture Documentation

> **Official architecture reference for the PhisMail repository.**
> This document describes the complete technical design of the system, covering every layer from HTTP ingestion to final verdict rendering.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [High-Level Architecture](#2-high-level-architecture)
3. [Email Analysis Pipeline](#3-email-analysis-pipeline)
4. [URL Analysis Pipeline](#4-url-analysis-pipeline)
5. [Feature Extraction Layer](#5-feature-extraction-layer)
6. [Rule Engine and Risk Scoring](#6-rule-engine-and-risk-scoring)
7. [Detection Modules](#7-detection-modules)
8. [Data Storage and Models](#8-data-storage-and-models)
9. [API Layer](#9-api-layer)
10. [Frontend Interface](#10-frontend-interface)
11. [Security Considerations](#11-security-considerations)
12. [Limitations and Future Improvements](#12-limitations-and-future-improvements)

---

## 1. Project Overview

### What is PhisMail?

PhisMail is a **SOC-grade phishing investigation platform** — a full-stack cybersecurity tool designed to analyze suspicious emails and URLs for phishing indicators. It is built for security analysts, blue teams, and individuals who need to assess whether a received email or link is a phishing attempt before interacting with it.

### The Problem It Solves

Phishing remains one of the most prevalent vectors for initial access in cyberattacks. Manually analyzing a suspicious email requires cross-referencing SPF/DKIM/DMARC headers, checking domain registration age, inspecting redirect chains, looking up threat intelligence feeds, and analyzing language patterns — a process that takes expert knowledge and significant time. PhisMail automates this entire forensic process in a single pipeline, producing a verdict, a risk score, and a detailed breakdown of every detection signal fired.

### Type of Tool

PhisMail is a **multi-signal phishing detection engine** combining:

- **Static email forensics** — parsing authentication headers, tracking SMTP hops, detecting spoofing
- **Structural URL analysis** — entropy scoring, obfuscation detection, redirect tracing
- **Domain intelligence** — WHOIS, DNS, typosquat and homograph detection
- **Threat intelligence** — real-time lookups against OpenPhish, PhishTank, and URLhaus
- **NLP-based social engineering detection** — keyword and pattern matching for urgency, credential harvesting, and impersonation
- **Risk scoring with explainability** — dual-bucket scoring engine with SHAP-compatible top contributor attribution

### Overall Workflow

```
User submits .eml file or suspicious URL
            ↓
FastAPI validates and enqueues the job
            ↓
Celery worker runs 9-stage analysis pipeline
            ↓
Results stored in PostgreSQL
            ↓
Frontend polls for completion and renders full report
            ↓
Analyst sees: SAFE / MARKETING / SUSPICIOUS / PHISHING
```

---

## 2. High-Level Architecture

### Component Map

```
┌─────────────────────────────────────────────────────────────────────┐
│                          User Browser                               │
│              Next.js Frontend (React / TypeScript)                  │
│    Dashboard · Submit · Analysis Results · IOC Export               │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ HTTP (port 80)
┌───────────────────────────▼─────────────────────────────────────────┐
│                    NGINX Reverse Proxy                               │
│       /api/*  →  backend:8000    /  →  frontend:3000                │
└────────────────┬───────────────────────────────┬────────────────────┘
                 │                               │
┌────────────────▼────────────┐   ┌──────────────▼──────────────────┐
│   FastAPI Backend           │   │   Next.js Server (SSR)          │
│   (uvicorn, port 8000)      │   │   (port 3000)                   │
│                             │   │                                  │
│  • POST /analyze/email      │   │  • /          (Dashboard)        │
│  • POST /analyze/url        │   │  • /submit    (Upload)           │
│  • GET  /analysis/{id}      │   │  • /analysis/[id] (Results)     │
│  • GET  /report/{id}        │   │                                  │
│  • GET  /report/{id}/export │   └─────────────────────────────────┘
│  • GET  /analyses           │
└────────────────┬────────────┘
                 │ Enqueue task
┌────────────────▼────────────────────────────────────────────────────┐
│                    Redis (port 6379)                                 │
│    DB 0: App cache  ·  DB 1: Celery broker  ·  DB 2: Celery results │
└────────────────┬────────────────────────────────────────────────────┘
                 │ Consume task
┌────────────────▼────────────────────────────────────────────────────┐
│                 Celery Worker                                        │
│            run_analysis_pipeline()                                   │
│                                                                      │
│  1. email_parser          →  Parse .eml file                        │
│  2. header_analyzer       →  SPF / DKIM / DMARC / spoofing          │
│  3. url_analyzer          →  Structural + obfuscation features       │
│  4. domain_intelligence   →  WHOIS + DNS + homograph                │
│  5. phishing_language_detector → NLP keyword scoring                │
│  6. attachment_risk_detector   → Metadata-only attachment scan      │
│  7. feature_builder       →  Aggregate ~80 features                 │
│  8. rule_engine           →  Dual-bucket risk scoring               │
│  9. report_generator      →  Assemble investigation report          │
└────────────────┬────────────────────────────────────────────────────┘
                 │ Persist results
┌────────────────▼────────────────────────────────────────────────────┐
│                 PostgreSQL (port 5432)                               │
│  AnalysisJob · ParsedEmail · ExtractedUrl · Indicator               │
│  DomainIntelligence · ThreatIntelHit · FeatureVector                │
│  InvestigationReport · AuditLog · MLModel                           │
└─────────────────────────────────────────────────────────────────────┘
```

### Technology Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js 15, React 19, TypeScript, Tailwind CSS v4 |
| Backend API | FastAPI (Python 3.12), uvicorn, slowapi (rate limiting) |
| Task Queue | Celery 5, Redis 7 |
| Database | PostgreSQL 16, SQLAlchemy ORM, Alembic migrations |
| Caching | Redis (DB 0), 24-hour TTL for domain/threat lookups |
| Reverse Proxy | NGINX (alpine) |
| Observability | Prometheus metrics, structlog (JSON structured logging) |
| Containerisation | Docker Compose (6 services) |
| ML Interface | scikit-learn / XGBoost compatible (joblib model loading) |

---

## 3. Email Analysis Pipeline

When a user uploads a `.eml` file, the following 9-stage pipeline executes asynchronously inside the Celery worker. The orchestrator is `backend/app/workers/pipeline.py` → `run_analysis_pipeline()`.

---

### Stage 1 — Email Parsing
**Module:** `backend/app/services/email_parser/parser.py`

The raw `.eml` file is read from disk and parsed using the `mailparser` library. Extracted fields:

- `sender` (From header, full address with display name)
- `reply_to`, `return_path` (separate envelope addresses)
- `subject`
- `body_text` (plain-text part)
- `body_html` (HTML part)
- `headers` (full raw headers dict for deep inspection)
- `attachments` (list of: filename, content_type, size_bytes, sha256 hash)
- `originating_ip` (extracted from `X-Originating-IP` or the first external `Received` header)
- `urls` (extracted from both HTML href attributes and plain-text patterns)

The parsed data is persisted to the `ParsedEmail` table.

---

### Stage 2 — Header Authentication Analysis
**Module:** `backend/app/services/header_analysis/header_analyzer.py`

The `analyze_headers()` function inspects the email headers for authentication signals and spoofing indicators.

**Authentication parsing:**
- Reads the `Authentication-Results` header.
- Extracts `spf=`, `dkim=`, `dmarc=` result values via regex.
- Maps `pass` / `bestguesspass` → `True`; `fail` / `softfail` / `hardfail` / `temperror` / `permerror` → `False`; absent → `None`.

**Mismatch detection:**
- `reply_to_mismatch` — From domain ≠ Reply-To domain
- `return_path_mismatch` — From domain ≠ Return-Path domain
- `sender_domain_mismatch` — all three domains disagree (strong spoofing signal)

**Infrastructure signals:**
- `bulk_mail_indicator` — presence of `List-Unsubscribe`, `feedback-id`, `X-Mailer`, etc.
- `esp_detected` — matches known ESP names (SendGrid, Mailchimp, Amazon SES, HubSpot, etc.) in email header values
- `num_received_headers` / `smtp_hops` — count of Received headers in the chain

**Display name brand spoofing:**
- Extracts display name from `From: "Display Name" <email@domain>` format.
- Checks if the display name contains any entry from a 25+ brand dictionary (`BRAND_DOMAIN_MAP`).
- If a brand match is found, verifies whether the actual sending domain matches a known-legitimate domain for that brand.
- Generic terms (`helpdesk`, `admin`, `support`, `security`) are always flagged when sent from an external domain.
- Sets `display_name_brand_spoofing = True` when mismatch is confirmed.

---

### Stage 3 — URL Structural Analysis
**Module:** `backend/app/services/url_analysis/url_analyzer.py`

Each URL extracted from the email body is analysed independently. The `analyze_url()` function populates a `UrlAnalysisResult` object with:

- **Structural features**: `url_length`, `num_dots`, `num_subdomains`, `num_hyphens`, `num_special_chars`, `num_query_parameters`, `num_fragments`
- **Risk indicators**: `contains_ip` (URL uses raw IP address), `is_shortened` (known shorteners: bit.ly, t.co, etc.), `has_https`, `entropy_score` (Shannon entropy of the URL string)
- **Obfuscation indicators**: `percent_encoding_count`, `hex_encoding_count`, `double_slash_redirect`, `encoded_characters_ratio`, `username_in_url`, `mixed_case_domain`, `long_query_string`
- **Brand detection**: `brand_keyword_present` (known brand names appearing in URL path/domain)

**Redirect tracing** (`redirect_tracker.py`): For each URL, an HTTP HEAD/GET chain is followed, recording `redirect_count`, `redirect_chain` (JSON list of hops), `final_destination`, `redirect_to_different_domain`, `redirect_to_ip`, and `final_domain_mismatch`.

Results are stored in the `ExtractedUrl` table.

---

### Stage 4 — Domain Intelligence
**Module:** `backend/app/services/domain_intelligence/`

Performed on the primary domain of the email's sender and/or extracted URLs. Results are cached in Redis for 24 hours to avoid hammering external APIs.

**WHOIS Lookup** (`whois_lookup.py`):
- Uses the `python-whois` library with tenacity retry logic (3 attempts, exponential backoff).
- Extracts: `registrar`, `registration_date`, `expiry_date`, `domain_age_days`, `nameservers`.
- Handles both list and string responses from the WHOIS library.

**DNS Analysis** (`dns_analysis.py`):
- Queries A, MX, TXT, NS records via `dnspython`.
- Detects `has_spf_record` (presence of `v=spf1` in TXT records).
- Detects `has_dmarc_record` (queries `_dmarc.{domain}` for a TXT record).
- Returns per-record-type results with graceful per-record error handling.

**Homograph / Typosquat Detection** (`homograph_detector.py`):
- Checks for Unicode lookalike characters in domain names (Punycode / IDN homograph attacks).
- Computes a `similarity_score` against known brand domains.
- Flags `is_homograph` and sets `matched_brand` if a close match is found.

Results are stored in the `DomainIntelligence` table.

---

### Stage 5 — NLP Phishing Language Detection
**Module:** `backend/app/services/nlp_analysis/phishing_language_detector.py`

The `analyze_phishing_language()` function combines the email subject, plain-text body, and HTML body (with tags stripped) into a single text corpus and scans it with keyword lists and regex patterns.

| Signal Category | Description |
|---|---|
| `urgency_keyword_count` | Words like "urgent", "expire", "act now", "final notice" |
| `credential_request_keywords` | Phrases like "verify your account", "reset your password", "login credentials" |
| `financial_request_keywords` | Words like "wire transfer", "invoice", "unauthorized transaction", "you have won" |
| `security_alert_keywords` | Phrases like "security alert", "suspicious login", "account compromised" |
| `imperative_language_score` | Regex patterns: "click here", "download this", "follow the link" |
| `webmail_phishing_phrase_count` | Phrases targeting email credential harvesting: "pending mail", "mailbox quota", "verify your mailbox" |
| `helpdesk_impersonation_detected` | Phrases mimicking IT staff: "helpdesk administrator", "IT support team", "mailbox administrator" |
| `generic_anchor_link_detected` | Generic link text: "click here to login", "verify here", "access here" |

Composite scores computed:
- `threat_language_score = min(total_signals / 10.0, 1.0)`
- `sentiment_score` — weighted blend of urgency, security, and credential counts
- `imperative_language_score = min(imperative_count / 5.0, 1.0)`

The `detected_patterns` list records exactly which patterns fired (e.g., `"urgency:act now"`, `"webmail:pending mail"`) — these are passed to the risk scorer for contextual detail generation.

---

### Stage 6 — Attachment Risk Analysis
**Module:** `backend/app/services/attachment_analysis/attachment_risk_detector.py`

> **Important:** PhisMail **never executes or decompresses attachment files**. Only metadata is inspected. This is intentional for safety.

For each attachment in the email:

- **Executable detection**: checks extension against a known-bad list (`.exe`, `.com`, `.scr`, `.pif`, `.bat`, `.cmd`, `.msi`, etc.)
- **Script detection**: `.vbs`, `.ps1`, `.js`, `.wsf`, `.hta`, `.jar`
- **Macro document detection**: `.doc`, `.docm`, `.xls`, `.xlsm`, `.ppt`, `.pptm`
- **Archive detection**: `.zip`, `.rar`, `.7z`, `.tar`, `.gz`
- **Double extension detection**: e.g., `document.pdf.exe` — the visible extension hides the real one
- **MIME type mismatch**: the declared `Content-Type` doesn't match the file extension

Output: `AttachmentRiskResult` with boolean flags and a composite `risk_score` (0.0–1.0).

---

### Stage 7 — Feature Engineering
**Module:** `backend/app/services/feature_engineering/feature_builder.py`

The `build_feature_vector()` function aggregates all outputs from stages 2–6 into a single flat Python dict of `~80 float features`. This is the input to both the rule engine and any trained ML model.

Each feature is a `float` (binary signals are `1.0` or `0.0`; count-based signals are the raw count; scores are normalised `0.0–1.0`).

All features are persisted to the `FeatureVector` table (one row per feature per analysis) to support future ML model retraining.

See [Section 5](#5-feature-extraction-layer) for the complete feature breakdown.

---

### Stage 8 — Risk Scoring
**Module:** `backend/app/services/risk_scoring/rule_engine.py`

The `calculate_risk_score()` function applies the dual-bucket scoring model and generates the final verdict. See [Section 6](#6-rule-engine-and-risk-scoring) for full details.

---

### Stage 9 — Report Generation
**Module:** `backend/app/services/reporting/report_generator.py`

Assembles the final `InvestigationReport` record:

- `verdict` and `risk_score`
- `phishing_probability` (from ML classifier if available)
- `indicators` list (sorted by severity: CRITICAL → HIGH → MEDIUM → LOW)
- `top_contributors` (SHAP-like top-10 feature attributions)
- `email_info` (sender, reply_to, subject, originating_ip, attachment_count)
- `url_analysis_results` (one entry per URL with redirect chain)
- `domain_intelligence` (WHOIS + DNS summary)
- `threat_intel_hits` (feed matches with confidence scores)

Report is saved to the `InvestigationReport` table and the `AnalysisJob.status` is set to `COMPLETE`.

---

## 4. URL Analysis Pipeline

When a user submits a raw URL (rather than an email file), a simplified pipeline runs — also in `pipeline.py` via the same `run_analysis_pipeline()` task but with `artifact_type = "url"`.

### Step-by-step

**1. URL Normalization** (`api/analysis.py`)
- The frontend auto-prepends `https://` if no scheme is present.
- The backend validates the scheme is `http://` or `https://`.
- SHA256 hash of the normalised URL is computed for deduplication.

**2. Structural Analysis** (`url_analyzer.py`)
- Same URL structural and obfuscation analysis as Stage 3 of the email pipeline.
- Computes length, entropy, subdomain count, IP presence, shortener detection, obfuscation features.

**3. Redirect Tracing** (`redirect_tracker.py`)
- Follows the redirect chain (HTTP HEAD/GET) recording each hop.
- Detects cross-domain redirects, redirects to IP addresses, and meta-refresh redirects.
- Records `final_destination` and `final_domain_mismatch`.

**4. Domain Intelligence** (`whois_lookup.py`, `dns_analysis.py`, `homograph_detector.py`)
- Same WHOIS/DNS/homograph analysis as Stage 4 of the email pipeline.
- Applied to the URL's registered domain.

**5. Threat Intelligence** (`threat_intel_service.py`)
- Asynchronous concurrent lookups against OpenPhish, PhishTank, and URLhaus.
- Cached per URL for 24 hours.

**6. Feature Engineering** (`feature_builder.py`)
- A URL-specific subset of features is built (URL structural, obfuscation, domain intel, threat intel).
- Header and NLP features are absent for URL-only analysis.

**7. Risk Scoring** (`rule_engine.py`)
- Same dual-bucket engine. URL-only scoring omits header and NLP features.
- CONTENT_ONLY protection still applies (NLP features alone cannot produce PHISHING).

**8. Report Generation** (`report_generator.py`)
- Assembles report with URL analysis results, domain intelligence, and threat intel hits.

---

## 5. Feature Extraction Layer

All features are assembled by `feature_builder.py` into a flat `Dict[str, float]`. There are approximately 80 features across 12 categories.

### Category 1 — Email Header Authentication (14 features)

| Feature | Type | Description |
|---|---|---|
| `spf_pass` | binary | SPF authentication passed |
| `dkim_pass` | binary | DKIM signature verified |
| `dmarc_pass` | binary | DMARC policy satisfied |
| `spf_fail` | binary | SPF explicitly failed |
| `dkim_fail` | binary | DKIM explicitly failed |
| `dmarc_fail` | binary | DMARC explicitly failed |
| `authentication_all_pass` | binary | All three auth mechanisms passed |
| `reply_to_mismatch` | binary | Reply-To domain differs from sender |
| `return_path_mismatch` | binary | Return-Path domain differs from sender |
| `sender_domain_mismatch` | binary | Three domains disagree |
| `bulk_mail_indicator` | binary | Bulk mail headers present |
| `esp_detected` | binary | Known ESP (SendGrid, Mailchimp etc.) detected |
| `num_received_headers` | count | Number of Received headers (SMTP hops) |
| `display_name_brand_spoofing` | binary | Display name contains brand but sender domain doesn't match |

### Category 2 — URL Structural (12 features)

| Feature | Type | Description |
|---|---|---|
| `url_length` | count | Total URL length in characters |
| `num_dots` | count | Number of dots in URL |
| `num_subdomains` | count | Number of subdomain levels |
| `num_hyphens` | count | Hyphens in hostname |
| `num_special_chars` | count | Special characters in URL |
| `contains_ip_address` | binary | URL uses raw IP instead of domain |
| `contains_at_symbol` | binary | @ present in URL (credential spoofing) |
| `num_query_parameters` | count | Number of query string parameters |
| `url_entropy_score` | float | Shannon entropy of URL string (0–1) |
| `num_fragments` | count | URL fragment (#) count |
| `has_https` | binary | URL uses HTTPS |
| `url_shortened` | binary | URL from known shortening service |

### Category 3 — URL Obfuscation (7 features)

| Feature | Type | Description |
|---|---|---|
| `percent_encoding_count` | count | %XX encoded characters |
| `hex_encoding_count` | count | Hex-encoded characters |
| `double_slash_redirect` | binary | `//` redirect present |
| `encoded_characters_ratio` | float | Ratio of encoded to total characters |
| `username_in_url` | binary | Credentials segment before @ |
| `mixed_case_domain` | binary | Domain uses mixed case |
| `long_query_string` | binary | Query string exceeds threshold |

### Category 4 — Domain Intelligence (11 features)

| Feature | Type | Description |
|---|---|---|
| `domain_age_days` | count | Domain age in days |
| `domain_very_recent` | binary | Domain < 7 days old |
| `domain_recent_registration` | binary | Domain 7–30 days old |
| `domain_expiry_days` | count | Days until domain expires |
| `domain_registrar_known` | binary | Registrar field populated |
| `num_nameservers` | count | Number of nameservers |
| `has_mx_record` | binary | MX record exists |
| `has_txt_record` | binary | TXT record exists |
| `has_spf_record` | binary | SPF TXT record present |
| `has_dmarc_record` | binary | DMARC TXT record present |
| `dns_record_count` | count | Total DNS record count |

### Category 5 — Domain Reputation (5 features, populated from external sources)

`tld_risk_score`, `domain_popularity_rank`, `asn_reputation_score`, `hosting_provider_known`, `country_risk_score`

### Category 6 — Threat Intelligence (6 features)

| Feature | Type | Description |
|---|---|---|
| `openphish_match` | binary | URL in OpenPhish community feed |
| `phishtank_match` | binary | URL in PhishTank database |
| `urlhaus_match` | binary | URL in URLhaus malware feed |
| `domain_blacklisted` | binary | Domain on any blocklist |
| `ip_blacklisted` | binary | IP address on any blocklist |
| `threat_confidence_score` | float | Fraction of feeds that matched (0–1) |

### Category 7 — Redirect Behaviour (5 features)

`redirect_count`, `redirect_to_different_domain`, `redirect_to_ip`, `final_domain_mismatch`, `meta_refresh_detected`

### Category 8 — Social Engineering NLP (10 features)

| Feature | Type | Description |
|---|---|---|
| `urgency_keyword_count` | count | Urgency keywords found |
| `credential_request_keywords` | count | Credential harvesting phrases |
| `financial_request_keywords` | count | Financial manipulation keywords |
| `security_alert_keywords` | count | Security alert phrases |
| `threat_language_score` | float | Composite threat language (0–1) |
| `sentiment_score` | float | Weighted urgency/security sentiment (0–1) |
| `imperative_language_score` | float | Click/download/verify imperatives (0–1) |
| `webmail_phishing_phrase_count` | count | Webmail credential-harvesting phrases |
| `helpdesk_impersonation_detected` | binary | IT helpdesk/admin impersonation phrases |
| `generic_anchor_link_detected` | binary | "Click here" / "login here" generic anchors |

### Category 9 — Brand Impersonation (6 features)

`brand_keyword_present`, `brand_domain_similarity_score`, `brand_typosquat_distance`, `brand_homograph_detected`, `brand_sender_domain_match`, `brand_sender_domain_mismatch`

### Category 10 — Attachment Risk (7 features)

`attachment_count`, `has_executable_attachment`, `has_script_attachment`, `has_macro_document`, `double_extension_detected`, `archive_with_executable`, `mime_mismatch_detected`

### Category 11 — Email Structure (10 features)

`num_urls_in_email`, `num_external_domains`, `html_to_text_ratio`, `num_images`, `num_forms`, `javascript_in_email`, `hidden_links_detected`, `has_unsubscribe_link`, `has_tracking_pixel`, `marketing_template_signals`

### Category 12 — Temporal (3 features)

`domain_age_hours`, `email_sent_outside_business_hours`, `campaign_activity_frequency`

---

## 6. Rule Engine and Risk Scoring

**Module:** `backend/app/services/risk_scoring/rule_engine.py`

### Dual-Bucket Architecture

The scoring engine uses a **suspicion minus trust** model to produce a final risk score:

```
risk_score = suspicion_score − trust_score
risk_score = clamp(risk_score, 0, 100)
```

This approach reduces false positives on legitimate bulk mail (which accumulates trust signals like SPF pass + DMARC pass + List-Unsubscribe + known ESP) even when it contains some superficially suspicious NLP patterns.

---

### Suspicion Bucket

Each feature with a non-zero value contributes `weight × value` to the raw suspicion score. Key weights:

| Signal | Weight | Rationale |
|---|---|---|
| Threat intel match (any feed) | 50.0 | Confirmed active phishing site |
| Executable / macro attachment | 35–40 | Primary malware vector |
| Double extension detected | 40.0 | Classic malware delivery tactic |
| Domain very recent (< 7 days) | 40.0 | Fresh domain = likely phishing |
| DMARC fail | 30.0 | Domain policy explicitly violated |
| Brand sender domain mismatch | 30.0 | Impersonation confirmed |
| Brand homograph detected | 30.0 | Punycode lookalike domain |
| Contains IP address URL | 30.0 | Legitimate services don't use bare IPs |
| Display name brand spoofing | 35.0 | Header-level impersonation |
| DKIM fail | 25.0 | Signature invalid or absent |
| Helpdesk impersonation | 25.0 | Social engineering persona |
| Domain recent registration (7–30d) | 25.0 | Probable short-lived phishing domain |
| Generic anchor link | 20.0 | Body-level social engineering |
| SPF fail | 20.0 | Sending server unauthorised |
| Reply-to mismatch | 15.0 | Intercept-reply tactic |
| Webmail phishing phrases | 15.0 per occurrence | Mailbox credential harvesting |
| Credential keywords | 10.0 per occurrence | Data harvesting language |

---

### Trust Bucket

Trust signals **reduce** the effective score:

| Signal | Weight | Cap |
|---|---|---|
| DMARC pass | 20.0 | — |
| Authentication all pass | 15.0 | — |
| DKIM pass | 15.0 | — |
| Bulk mail indicator | 15.0 | — |
| SPF pass | 10.0 | — |
| ESP detected | 10.0 | — |
| Brand sender domain match | 10.0 | — |
| URL domain matches sender | 10.0 | — |
| URL subdomain of sender | 10.0 | — |
| Domain age (days × 0.01) | variable | capped at 30.0 |
| CDN domain detected | 5.0 | — |
| Marketing template signals | 5.0 | — |

---

### Content-Only Protection

NLP and social engineering features (`urgency_keyword_count`, `credential_request_keywords`, `financial_request_keywords`, `security_alert_keywords`, `threat_language_score`, `imperative_language_score`, `webmail_phishing_phrase_count`, `helpdesk_impersonation_detected`, `generic_anchor_link_detected`) are classified as **content-only features**.

If 100% of the suspicion score comes from content-only features (i.e., there are no header, URL, domain, or attachment signals), the effective suspicion score is **capped at 74** — just below the PHISHING threshold. This prevents a plain-text email with aggressive marketing language from being incorrectly classified as phishing.

`display_name_brand_spoofing` is **not** a content-only feature — it is a header signal that can contribute to a PHISHING verdict independently.

---

### Verdict Thresholds

| Risk Score | Verdict | Meaning |
|---|---|---|
| ≥ 75 | **PHISHING** | High-confidence phishing attempt |
| 50–74 | **SUSPICIOUS** | Significant indicators; treat with caution |
| 20–49 | **MARKETING** | Likely bulk commercial email |
| 0–19 | **SAFE** | No significant risk signals detected |

---

### Indicators and Explainability

For every suspicion feature that fires, an `Indicator` record is generated:

```json
{
  "indicator_type": "display_name_brand_spoofing",
  "severity": "HIGH",
  "detail": "Display name \"Microsoft Outlook\" contains brand keyword \"microsoft\" but the sending domain (unimedceara.com.br) is not a legitimate microsoft domain — classic display-name spoofing.",
  "confidence": 0.70,
  "source_module": "risk_scorer"
}
```

Indicators are sorted by severity (CRITICAL → HIGH → MEDIUM → LOW) for display.

The **top-10 contributors** list (both suspicion and trust) provides SHAP-compatible attribution:

```json
{
  "feature_name": "display_name_brand_spoofing",
  "attribution_score": 35.0,
  "direction": "phishing"
}
```

This allows analysts to understand exactly which signals drove the verdict.

---

## 7. Detection Modules

### Header Analysis (`header_analysis/header_analyzer.py`)

Validates email authentication infrastructure and detects address-level spoofing. The only module that can detect spoofing even when the email body is completely benign. Critical for catching brand impersonation attacks where a legitimate-looking display name masks a fraudulent sender domain.

### URL Structural Analysis (`url_analysis/url_analyzer.py`)

Inspects URLs without making network requests. Calculates Shannon entropy (high entropy = likely DGA-generated domain), counts obfuscation indicators, and detects credential-spoofing patterns (`user@paypal.com@evil.com`). Effective against freshly registered domains with no threat intel history.

### Redirect Tracker (`url_analysis/redirect_tracker.py`)

Follows HTTP redirect chains to expose multi-hop evasion (e.g., a legitimate-looking link → URL shortener → phishing page). Detects redirects to IP addresses and cross-domain final destinations.

### Domain Intelligence (`domain_intelligence/`)

Three sub-modules work together:

- **WHOIS** reveals domain registration age — a highly effective signal since phishing domains are typically registered days before campaigns launch.
- **DNS** confirms the domain's infrastructure (MX, SPF, DMARC records) and identifies domains with minimal DNS footprint.
- **Homograph detector** catches Unicode domain impersonation (e.g., `pаypal.com` with a Cyrillic `а`).

### Threat Intelligence (`threat_intelligence/threat_intel_service.py`)

Runs concurrent async queries to three external feeds. If any feed matches, the score jumps by 50 points — sufficient alone to trigger a SUSPICIOUS verdict. Operates with graceful degradation: if a feed API is unreachable, its result is skipped without failing the analysis.

### NLP Phishing Language Detector (`nlp_analysis/phishing_language_detector.py`)

Pure regex and keyword matching — no ML model required. Targets four distinct social engineering strategies: urgency manipulation, credential harvesting, financial fraud, and security alert impersonation. Three specialised sub-detectors target webmail credential harvesting (the most common corporate phishing pattern), IT helpdesk impersonation, and generic anchor text (often seen in plain-text spear phishing).

### Attachment Risk Detector (`attachment_analysis/attachment_risk_detector.py`)

Metadata-only analysis — no code execution, no decompression, no sandboxing. Focuses on structural indicators: dangerous extensions, double extensions designed to fool Windows (which hides known extensions by default), macro-enabled documents, and MIME type mismatches. These patterns are effective against known malware delivery techniques without requiring any threat intel.

### Feature Builder (`feature_engineering/feature_builder.py`)

Not a detector itself, but the aggregation layer that normalises all module outputs into a consistent float vector. It also handles cross-module signals — for example, checking whether the URL domain is a subdomain of the sender domain (trust signal) or a completely unrelated domain (suspicion signal), including CDN whitelist logic.

### Rule Engine (`risk_scoring/rule_engine.py`)

The final arbitration layer. Applies domain expert knowledge encoded as weights to produce a single interpretable risk score. The dual-bucket model is a deliberate design choice over a single-feature-sum approach, as it prevents legitimate bulk email with some suspicious vocabulary from scoring disproportionately high.

---

## 8. Data Storage and Models

**Module:** `backend/app/models/models.py`

All models inherit from SQLAlchemy's declarative base. Alembic manages schema migrations.

### AnalysisJob

The primary tracking entity for every submission.

| Column | Type | Description |
|---|---|---|
| `id` | UUID (PK) | Unique analysis identifier |
| `artifact_type` | String | `email` or `url` |
| `artifact_hash` | String | SHA256 of file or URL (dedup key) |
| `artifact_location` | String | Path on disk for `.eml` files |
| `original_filename` | String | Uploaded filename |
| `submitted_url` | String | For URL analyses |
| `status` | Enum | `PENDING`, `PROCESSING`, `COMPLETE`, `FAILED` |
| `error_message` | Text | Failure reason if status = FAILED |
| `created_at` | DateTime | Submission time |
| `updated_at` | DateTime | Last status change |
| `completed_at` | DateTime | Completion time |

Index on `(artifact_hash, status)` for deduplication lookups.

### ParsedEmail

Raw parsed fields from the .eml file.

| Column | Type | Description |
|---|---|---|
| `sender` | String | From address |
| `reply_to` | String | Reply-To address |
| `return_path` | String | Return-Path address |
| `subject` | Text | Email subject |
| `body_text` | Text | Plain-text body |
| `body_html` | Text | HTML body |
| `headers` | JSON | Full headers dict |
| `attachments_meta` | JSON | Attachment metadata list |
| `originating_ip` | String | Client IP if present |
| `spf_pass` / `dkim_pass` / `dmarc_pass` | Boolean | Auth results |
| `reply_to_mismatch` / `return_path_mismatch` / `sender_domain_mismatch` | Boolean | Mismatch flags |

### ExtractedUrl

One record per URL found in the email or submitted directly.

| Column | Type | Description |
|---|---|---|
| `url` | Text | Full URL string |
| `domain` | String | Extracted domain |
| `url_length`, `num_subdomains`, `entropy_score` | Float | Structural features |
| `contains_ip`, `is_shortened`, `has_https` | Boolean | Risk flags |
| `redirect_count` | Integer | Number of redirects followed |
| `redirect_chain` | JSON | List of intermediate URLs |
| `final_destination` | Text | End URL after redirects |
| `final_domain_mismatch` | Boolean | Final domain ≠ original domain |

### Indicator

One record per fired detection signal.

| Column | Type | Description |
|---|---|---|
| `indicator_type` | String | Feature name (e.g., `dmarc_fail`) |
| `severity` | Enum | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `detail` | Text | Human-readable explanation |
| `confidence` | Float | 0.0–1.0 |
| `source_module` | String | Module that generated this indicator |

### DomainIntelligence

WHOIS and DNS enrichment for a domain.

| Column | Type | Description |
|---|---|---|
| `domain` | String | The analysed domain |
| `registrar` | String | Domain registrar name |
| `registration_date` / `expiry_date` | DateTime | WHOIS dates |
| `domain_age_days` | Integer | Days since registration |
| `nameservers` | JSON | NS record list |
| `a_records` / `mx_records` / `txt_records` / `ns_records` | JSON | DNS records |
| `has_spf_record` / `has_dmarc_record` | Boolean | Policy record presence |
| `is_homograph` | Boolean | Unicode homograph detected |
| `brand_impersonation` | String | Matched brand name |

### ThreatIntelHit

Record for each threat intelligence feed match.

| Column | Type | Description |
|---|---|---|
| `source` | String | `openphish`, `phishtank`, `urlhaus` |
| `matched_url` / `matched_domain` | String | What was matched |
| `confidence_score` | Float | Feed-provided confidence |
| `feed_data` | JSON | Raw feed response |

### FeatureVector

Persistent feature store for ML retraining.

| Column | Type | Description |
|---|---|---|
| `feature_name` | String | Feature identifier (e.g., `url_entropy_score`) |
| `feature_value` | Float | Computed value |
| `feature_category` | String | Category grouping |

Index on `(analysis_id, feature_name)` for fast model training queries.

### InvestigationReport

Final analysis output.

| Column | Type | Description |
|---|---|---|
| `verdict` | Enum | `SAFE`, `MARKETING`, `SUSPICIOUS`, `PHISHING` |
| `risk_score` | Float | 0–100 |
| `phishing_probability` | Float | ML classifier output (0–1) |
| `top_contributors` | JSON | Top-10 SHAP-like attributions |
| `full_report` | JSON | Complete structured report blob |

### AuditLog

Forensic event trail.

| Column | Type | Description |
|---|---|---|
| `event_type` | String | e.g., `ANALYSIS_STARTED`, `THREAT_INTEL_HIT` |
| `analysis_id` | UUID | Associated analysis |
| `actor` | String | System module or user |
| `detail` | Text | Event description |

### MLModel

Version registry for trained models.

| Column | Type | Description |
|---|---|---|
| `model_name` | String | Model identifier |
| `model_version` | String | Semantic version |
| `model_path` | String | Path to `.pkl` file |
| `accuracy_score` / `f1_score` | Float | Evaluation metrics |
| `is_active` | Boolean | Currently loaded model |

---

## 9. API Layer

**Modules:** `backend/app/api/analysis.py`, `backend/app/api/reports.py`, `backend/app/api/health.py`

All routes are prefixed `/api/v1/` and aggregated in `api/router.py`.

---

### POST `/api/v1/analyze/email`

Upload a `.eml` file for analysis.

**Request:** `multipart/form-data`
- `file` — `.eml` file, max 5 MB

**Validation:**
- File extension must be `.eml`
- File size must not exceed configured limit
- MIME type check

**Behaviour:**
1. Computes SHA256 hash of file content.
2. Queries for existing `COMPLETE` analysis with matching hash — returns cached result if found.
3. Saves file to `./storage/emails/{analysis_id}.eml`.
4. Creates `AnalysisJob` record with `status = PENDING`.
5. Dispatches `run_analysis_pipeline.apply_async(args=[analysis_id], queue="email")`.

**Response:** `200 OK`
```json
{
  "analysis_id": "uuid",
  "artifact_type": "email",
  "status": "pending",
  "created_at": "2026-03-13T10:00:00Z",
  "message": "Analysis queued successfully"
}
```

---

### POST `/api/v1/analyze/url`

Submit a URL for analysis.

**Request:** `application/json`
```json
{ "url": "https://suspicious-site.example.com/login" }
```

**Validation:**
- URL must start with `http://` or `https://`

**Behaviour:**
- Same dedup/queue/response pattern as email endpoint.

---

### GET `/api/v1/analysis/{analysis_id}`

Poll the status of an ongoing or completed analysis.

**Response:** `200 OK`
```json
{
  "analysis_id": "uuid",
  "artifact_type": "email",
  "status": "processing",
  "created_at": "...",
  "updated_at": "...",
  "completed_at": null,
  "error_message": null
}
```

Status values: `pending` → `processing` → `complete` | `failed`

---

### GET `/api/v1/analyses`

List recent analyses (paginated).

**Query params:** `page` (default 1), `per_page` (default 20, max 100)

**Response:**
```json
{
  "total": 142,
  "page": 1,
  "per_page": 20,
  "analyses": [{ "analysis_id": "...", "status": "complete", "verdict": "PHISHING", ... }]
}
```

---

### GET `/api/v1/report/{analysis_id}`

Fetch the full investigation report for a completed analysis.

**Response:** `200 OK`
```json
{
  "analysis_id": "uuid",
  "verdict": "PHISHING",
  "risk_score": 92.0,
  "phishing_probability": 0.95,
  "indicators": [
    {
      "indicator_type": "display_name_brand_spoofing",
      "severity": "HIGH",
      "detail": "Display name \"Microsoft Outlook\" ...",
      "confidence": 0.70,
      "source_module": "risk_scorer"
    }
  ],
  "extracted_urls": [...],
  "domain_intelligence": [...],
  "threat_intel_hits": [...],
  "top_contributors": [
    { "feature_name": "display_name_brand_spoofing", "attribution_score": 35.0, "direction": "phishing" }
  ]
}
```

Returns `404` if analysis not found, `400` if analysis is not yet complete.

---

### GET `/api/v1/report/{analysis_id}/export`

Export indicators and URLs as machine-readable IOCs.

**Query params:** `format` — `json` (default) | `csv` | `stix2`

**STIX2 format** produces a valid STIX 2.1 Bundle with `identity`, `indicator`, and `url` objects — suitable for direct import into threat intelligence platforms.

---

### Rate Limiting

All API endpoints are rate-limited to **100 requests per hour per IP address** via slowapi. Exceeding the limit returns `429 Too Many Requests`.

---

## 10. Frontend Interface

**Framework:** Next.js 15 (App Router), React 19, TypeScript, Tailwind CSS v4

**Theme:** Cybersecurity terminal aesthetic — dark background (`#0d1117`), neon blue (`#0070f3`) primary, neon green (`#00ff9d`) secondary, JetBrains Mono monospace font, animated matrix-rain canvas background.

---

### Dashboard (`src/app/page.tsx`)

The landing page lists all recent analyses in a paginated table (10 per page) showing submission time, artifact type, verdict badge, and risk score. Two quick-action cards link to the submission form. The `PipelineView` component renders a visual diagram of the 9-stage analysis pipeline.

---

### Submission Page (`src/app/submit/page.tsx`)

A tabbed interface with two modes:

**URL mode:**
- Text input with auto-prepend of `https://` if no scheme is present.
- Submits to `POST /api/v1/analyze/url`.

**Email mode:**
- Drag-and-drop zone accepting `.eml` files only, max 5 MB.
- Click-to-browse fallback.
- Submits to `POST /api/v1/analyze/email` as `multipart/form-data`.

On successful submission the router immediately navigates to `/analysis/{id}`.

---

### Analysis Results Page (`src/app/analysis/[id]/page.tsx`)

**While processing:** Renders the `AnalysisTimeline` component — a terminal-style interface showing:
- Progress ring (SVG, neon blue → neon green on completion)
- Current pipeline stage name and description
- Stage table with elapsed time per completed step
- Animated blinking dots for active stages
- Hairline progress bar with neon glow

Polls `GET /api/v1/analysis/{id}` every 3 seconds until `status === "complete"`.

**On completion:** Fetches full report from `GET /api/v1/report/{id}` and renders:

| Component | Content |
|---|---|
| `VerdictBadge` | Colour-coded verdict (red = PHISHING, amber = SUSPICIOUS, purple = MARKETING, green = SAFE) |
| `RiskGauge` | Circular gauge 0–100 with colour gradient |
| Stat cards | Risk score, indicator count, URLs analysed, threat intel hits, phishing probability |
| `IndicatorList` | Sortable table of all fired indicators with severity, detail, and confidence |
| `ExplainabilityChart` | Horizontal bar chart of top-10 feature attributions (phishing direction = red, safe direction = green) |
| `RedirectChainView` | Visualises multi-hop redirect chains with domain labels and cross-domain arrows |
| `DomainIntelCard` | WHOIS registration data, DNS records, homograph flag per domain |
| Threat intel section | Feed match cards with source, matched URL, and confidence score |

---

### API Client (`src/lib/api.ts`)

Fully typed TypeScript client. Uses the Fetch API against `NEXT_PUBLIC_API_URL` (defaults to `/api`). All responses are typed with interfaces matching the backend Pydantic schemas. Errors are thrown as `Error` objects with the server-returned message.

---

## 11. Security Considerations

### Untrusted Email Content

- `.eml` files are parsed purely in Python memory via `mailparser`. No email is rendered in a browser.
- HTML body content is **never injected directly into the frontend DOM** — it is stored in PostgreSQL and only accessed as a string for NLP text analysis and feature extraction.
- URL extraction uses regex and BeautifulSoup HTML parsing, not browser rendering.

### Attachments

- PhisMail performs **metadata-only attachment analysis**. Attachment bytes are inspected for extension, MIME type, and filename patterns only.
- No attachment is ever executed, decompressed, or opened.
- Attachment SHA256 hashes are computed for reference but the content is not further processed.
- This is a deliberate security boundary — sandbox execution (Cuckoo, etc.) is out of scope for this version.

### HTML Rendering

- The frontend does not render email HTML bodies. Body content is shown only as plain text in UI cards.
- The `ExplainabilityChart` and `IndicatorList` components display server-generated strings, not raw user content.
- React's JSX escapes all interpolated values, preventing XSS from malicious indicator `detail` strings.

### Malicious URLs

- URLs are only fetched during redirect tracing (the `redirect_tracker` module).
- Redirect tracing uses HTTP HEAD requests where possible to avoid downloading response bodies.
- No JavaScript is executed during URL analysis — no headless browser is used.
- Threat intelligence lookups submit only the URL string to external APIs, never fetching the suspicious page itself.

### Input Validation

- File uploads: extension check (`.eml` only), size limit (5 MB), MIME type validation.
- URL submissions: scheme validation (`http://` or `https://` only).
- All database queries use SQLAlchemy ORM parameterised queries — no raw SQL.
- API rate limiting (100 req/hour/IP) prevents abuse.

### Secret Management

- All API keys and database credentials are loaded from environment variables via pydantic-settings.
- The `.env` file is excluded from version control (`.gitignore`).
- `SECRET_KEY` must be changed before production deployment.

---

## 12. Limitations and Future Improvements

### Current Limitations

**Detection coverage:**
- Attachment analysis is metadata-only. Sandbox execution (dynamic analysis) would detect obfuscated payloads that evade static inspection.
- Threat intelligence coverage depends on three free/community feeds. A commercial feed (VirusTotal, Recorded Future, etc.) would improve zero-day URL detection.
- The NLP layer uses keyword matching. A fine-tuned transformer model (BERT, DeBERTa) would handle paraphrased or multi-language phishing content more effectively.
- Domain reputation features (`tld_risk_score`, `asn_reputation_score`, `country_risk_score`) are currently placeholder `0.0` values — integration with a reputation database would add significant signal.
- No OCR for image-based phishing (emails with text embedded in images to evade text analysis).
- No rendering of the final redirect destination to detect login form overlays or credential-capture pages.

**Infrastructure:**
- The Celery worker runs with a single instance. High-volume deployments should scale workers horizontally and tune concurrency.
- Redis is used for both caching and message brokering with no persistence configuration. A production deployment should configure Redis AOF/RDB persistence.
- No authentication on the API — any user can submit analyses and read all reports. Adding API key or OAuth2 authentication would be necessary for multi-tenant deployments.
- STIX2 export uses a basic bundle structure. A full CTI platform integration (MISP, OpenCTI) would require richer STIX object relationships.

**ML Model:**
- The ML classifier (`ml/classifier.py`) currently wraps the rule engine. A trained XGBoost or neural model using the `FeatureVector` table as training data has been scaffolded but not yet trained.
- No active learning loop — flagged false positives/negatives do not automatically feed back into training data.
- No model versioning workflow beyond the `MLModel` table schema.

### Suggested Improvements

| Area | Improvement |
|---|---|
| Attachment analysis | Integrate Cuckoo Sandbox or any.run API for dynamic analysis of macro documents and executables |
| Threat intelligence | Add VirusTotal URL scan, Google Safe Browsing, Cisco Talos |
| NLP | Fine-tune a BERT-based classifier on the `FeatureVector` training data |
| Domain reputation | Integrate Cisco Umbrella or DomainTools for ASN/popularity/TLD risk scores |
| Authentication | Add API key authentication or OAuth2 for multi-user deployments |
| Image analysis | Add OCR (Tesseract) to detect text embedded in phishing images |
| URL rendering | Add headless browser (Playwright) to screenshot and inspect the final URL destination |
| Training pipeline | Build automated retraining jobs using the `FeatureVector` store with human-verified labels |
| Alerting | Add webhook/email alert on CRITICAL verdict |
| MISP integration | Export indicators directly to MISP or OpenCTI via MISP API |
| Campaign clustering | Group related analyses by shared infrastructure (IP, registrar, domain pattern) |
| Dark mode / light mode | Full theme switching (currently dark-only) |

---

*Generated by architectural review of the PhisMail repository.*
*Backend: FastAPI + Celery + PostgreSQL + Redis | Frontend: Next.js + React + TypeScript*
