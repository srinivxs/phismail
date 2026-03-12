# PhisMail — API Reference

## Base URL

```
http://localhost/api/v1
```

---

## Analysis

### Submit Email

```
POST /analyze/email
Content-Type: multipart/form-data

file: <.eml file> (max 5MB)
```

**Response** `200 OK`:
```json
{
  "analysis_id": "uuid",
  "artifact_type": "email",
  "status": "pending",
  "message": "Analysis submitted successfully",
  "created_at": "2025-03-10T03:00:00Z"
}
```

**Errors**: `400` invalid file, `429` rate limit exceeded

---

### Submit URL

```
POST /analyze/url
Content-Type: application/json

{
  "url": "https://suspicious-site.com/login"
}
```

**Response** `200 OK`:
```json
{
  "analysis_id": "uuid",
  "artifact_type": "url",
  "status": "pending",
  "message": "URL analysis submitted"
}
```

---

### Get Analysis Status

```
GET /analysis/{analysis_id}
```

**Response** `200 OK`:
```json
{
  "analysis_id": "uuid",
  "artifact_type": "email",
  "status": "complete",
  "created_at": "2025-03-10T03:00:00Z"
}
```

Status values: `pending`, `processing`, `complete`, `failed`

---

### List Analyses

```
GET /analyses?page=1&per_page=20
```

**Response** `200 OK`:
```json
{
  "total": 42,
  "page": 1,
  "per_page": 20,
  "analyses": [...]
}
```

---

## Reports

### Get Investigation Report

```
GET /report/{analysis_id}
```

**Response** `200 OK`:
```json
{
  "analysis_id": "uuid",
  "verdict": "PHISHING",
  "risk_score": 86,
  "phishing_probability": 0.92,
  "indicators": [
    {"indicator_type": "openphish_match", "severity": "CRITICAL", "detail": "...", "confidence": 1.0}
  ],
  "extracted_urls": [...],
  "domain_intelligence": [...],
  "threat_intel_hits": [...],
  "top_contributors": [
    {"feature_name": "openphish_match", "attribution_score": 30.0, "direction": "phishing"}
  ]
}
```

---

### Export IOCs

```
GET /report/{analysis_id}/ioc?format=json
GET /report/{analysis_id}/ioc?format=csv
GET /report/{analysis_id}/ioc?format=stix2
```

---

## Health

```
GET /health          # Aggregate health
GET /health/db       # Database connectivity
GET /health/redis    # Redis connectivity
```

---

## Verdicts

| Verdict | Risk Score | Meaning |
|---|---|---|
| SAFE | 0–39 | No significant phishing indicators |
| SUSPICIOUS | 40–69 | Multiple moderate signals detected |
| PHISHING | 70–100 | High-confidence phishing detected |
