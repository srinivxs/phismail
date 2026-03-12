# PhisMail — Artifact Pipeline

## Overview

The artifact pipeline handles ingestion, validation, deduplication, and routing of submitted artifacts (emails and URLs) through the analysis engine.

## Pipeline Stages

### 1. Ingestion
- **Email**: `POST /api/v1/analyze/email` — multipart file upload (.eml, max 5MB)
- **URL**: `POST /api/v1/analyze/url` — JSON body with URL string

### 2. Validation
- File size check (configurable via `UPLOAD_MAX_SIZE_MB`)
- MIME type validation (must be `message/rfc822` for emails)
- URL format validation

### 3. Deduplication
- **Email**: SHA256 hash of raw file bytes
- **URL**: SHA256 of normalized URL (lowercased, trailing slash stripped)
- If hash exists and previous analysis is complete, returns existing `analysis_id`

### 4. Storage
- Emails stored to disk (`/app/storage/emails/{analysis_id}.eml`)
- Metadata persisted to `AnalysisJob` table

### 5. Queue Dispatch
- Celery task `run_analysis_pipeline` dispatched with `analysis_id`
- Task routed to appropriate queue based on artifact type

### 6. Pipeline Execution
```
Email Path: parse → headers → URLs → domain → NLP → attachments → features → scoring → report
URL Path:   analyze → domain → features → scoring → report
```

### 7. Result Retrieval
- `GET /api/v1/analysis/{id}` — poll status (pending/processing/complete/failed)
- `GET /api/v1/report/{id}` — full investigation report (once complete)
