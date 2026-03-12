# PhisMail

**SOC-grade phishing investigation platform for email and URL analysis.**

PhisMail runs a 9-stage forensic pipeline against suspicious `.eml` files and URLs. It validates email authentication, traces redirect chains, queries live threat intelligence feeds, scores social engineering language, and produces a structured verdict with SHAP-like feature attribution — all through a SOC-themed web dashboard.

---

## Architecture Overview

```
Browser (Next.js)
      |
   NGINX :80
   /api/* → FastAPI :8000        / → Next.js :3000
      |
   FastAPI
   Validates input · hashes artifact · creates job · enqueues to Celery
      |
   Redis  (broker DB1 · results DB2 · cache DB0)
      |
   Celery Worker — 9-stage pipeline
      |
   1. Email Parsing      — RFC 5322 / MIME decomposition
   2. Header Forensics   — SMTP hops, originating IP, X-headers
   3. Auth Verification  — SPF · DKIM · DMARC · display name spoofing
   4. URL Analysis       — entropy, obfuscation, redirect chain tracing
   5. Domain Intel       — WHOIS · DNS · homograph · typosquat detection
   6. Threat Intel       — OpenPhish · PhishTank · URLhaus (async, concurrent)
   7. NLP Detection      — urgency · credential · financial · impersonation
   8. Risk Scoring       — dual-bucket engine (~80 features, 12 categories)
   9. Report Generation  — verdict · indicators · IOC export
      |
   PostgreSQL  (results · feature vectors · audit log)
```

**Verdict tiers:** `SAFE` (0-19) · `MARKETING` (20-49) · `SUSPICIOUS` (50-74) · `PHISHING` (75-100)

---

## Features

| Layer | Capability |
|---|---|
| Header analysis | SPF / DKIM / DMARC parsing, reply-to mismatch, display name brand spoofing |
| URL analysis | Entropy scoring, obfuscation detection, live redirect chain tracing |
| Domain intelligence | WHOIS registration age, DNS enumeration, homograph and typosquat detection |
| Threat intelligence | Concurrent async queries to OpenPhish, PhishTank, and URLhaus |
| NLP detection | Urgency, credential harvesting, helpdesk impersonation, webmail phishing phrases |
| Attachment analysis | Executable / macro / double-extension detection (metadata-only, never executes) |
| Risk scoring | Dual-bucket suspicion minus trust engine with content-only false positive protection |
| Explainability | SHAP-compatible top-10 feature attribution per verdict |
| IOC export | STIX2 bundle, JSON, CSV |

---

## Prerequisites

- [Docker](https://www.docker.com/) and Docker Compose v2
- `PHISHTANK_API_KEY` and `URLHAUS_AUTH_KEY` are optional — the system degrades gracefully without them

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/srinivxs/phismail.git
cd phismail

# 2. Configure environment
cp .env.example .env
# Edit .env — change SECRET_KEY before first run

# 3. Start all services
docker compose up -d

# 4. Open the dashboard
open http://localhost
```

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `SECRET_KEY` | Yes | Change before production deployment |
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `REDIS_URL` | Yes | Redis connection string |
| `PHISHTANK_API_KEY` | No | Improves PhishTank hit rate |
| `URLHAUS_AUTH_KEY` | No | Improves URLhaus hit rate |
| `DEBUG` | No | Set `true` to enable `/docs` Swagger UI |
| `ML_MODEL_PATH` | No | Path to trained model; rule engine used if absent |

---

## Usage

### Analyze a suspicious email

Navigate to `http://localhost/submit`, select the `.eml` tab, upload a `.eml` file (max 5 MB), and click **Analyze Email**.

### Analyze a suspicious URL

Navigate to `http://localhost/submit`, select the **URL** tab, paste the URL, and click **Analyze URL**. The `https://` scheme is prepended automatically if omitted.

### Export IOCs

```bash
# STIX2 bundle
curl http://localhost/api/v1/report/{analysis_id}/export?format=stix2

# CSV
curl http://localhost/api/v1/report/{analysis_id}/export?format=csv

# JSON
curl http://localhost/api/v1/report/{analysis_id}/export?format=json
```

---

## API Reference

Full documentation: [`docs/API.md`](docs/API.md)

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/analyze/email` | Upload `.eml` file |
| `POST` | `/api/v1/analyze/url` | Submit URL |
| `GET` | `/api/v1/analysis/{id}` | Poll analysis status |
| `GET` | `/api/v1/report/{id}` | Fetch full investigation report |
| `GET` | `/api/v1/report/{id}/export` | Export IOCs (json / csv / stix2) |
| `GET` | `/api/v1/analyses` | List recent analyses |

---

## Local Development

### Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Celery worker
celery -A app.core.celery_app worker --loglevel=info --queues=email,url,enrichment,scoring,reports
```

### Frontend

```bash
cd frontend
npm install
npm run dev      # http://localhost:3000
npm run lint
npm run build
```

### Database migrations

```bash
cd backend
alembic upgrade head
alembic revision --autogenerate -m "description"
```

### Tests

```bash
# From repo root
python -m pytest tests/unit/ -v          # All 120 unit tests (~1s)
```

---

## Project Structure

```
phismail/
├── backend/
│   ├── app/
│   │   ├── api/             # FastAPI routers (analysis, reports, health)
│   │   ├── core/            # Config, database, Celery, logging, security
│   │   ├── ml/              # Classifier, SHAP explainer, model registry
│   │   ├── models/          # SQLAlchemy ORM models
│   │   ├── services/        # One module per analysis capability
│   │   ├── storage/         # Artifact store and file validation
│   │   ├── utils/           # Cache, validators, helpers
│   │   └── workers/         # Celery pipeline and task modules
│   └── requirements.txt
├── frontend/
│   └── src/
│       ├── app/             # Next.js App Router pages
│       ├── components/      # React components
│       └── lib/             # Typed API client
├── infrastructure/
│   └── nginx/nginx.conf
├── tests/
│   └── unit/                # 120 unit tests, no external dependencies
├── docs/
│   ├── API.md
│   └── Deployment.md
├── architecture/            # Component-level design documents
├── dataset/                 # Sample .eml test files (50 files)
├── docker-compose.yml
├── .env.example
└── SYSTEM_ARCHITECTURE.md
```

---

## Documentation

| Document | Description |
|---|---|
| [`SYSTEM_ARCHITECTURE.md`](SYSTEM_ARCHITECTURE.md) | Full system architecture reference |
| [`docs/API.md`](docs/API.md) | REST API endpoint documentation |
| [`docs/Deployment.md`](docs/Deployment.md) | Production deployment guide |
| [`architecture/`](architecture/) | Component-level design documents |

---

## Docker Services

| Service | Image | Port | Purpose |
|---|---|---|---|
| `nginx` | nginx:alpine | 80 | Reverse proxy |
| `backend` | custom | 8000 | FastAPI application |
| `celery-worker` | custom | - | Analysis pipeline worker |
| `frontend` | custom | 3000 | Next.js dashboard |
| `postgres` | postgres:16 | 5432 | Primary database |
| `redis` | redis:7 | 6379 | Broker and cache |

---

## License

MIT License

---

Built by [Srinivas V B](https://www.linkedin.com/in/srinivas-vb)
