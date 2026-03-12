# PhisMail — Deployment Architecture

## Docker Compose Services

| Service | Image | Port | Purpose |
|---|---|---|---|
| `postgres` | postgres:16-alpine | 5432 | Database (persistent volume) |
| `redis` | redis:7-alpine | 6379 | Cache + message broker |
| `backend` | Custom (Python 3.12) | 8000 | FastAPI application |
| `celery-worker` | Same as backend | — | Pipeline worker (5 queues) |
| `frontend` | Custom (Node.js) | 3000 | Next.js dashboard |
| `nginx` | nginx:alpine | 80 | Reverse proxy |

## Celery Queue Configuration

| Queue | Purpose |
|---|---|
| `email` | Email parsing and header analysis |
| `url` | URL structural analysis |
| `enrichment` | Domain intel, threat intel lookups |
| `scoring` | Feature aggregation, risk scoring |
| `reports` | Report generation |

## Environment Configuration

All configuration via environment variables (`.env` file). Key settings:
- `DATABASE_URL` — PostgreSQL connection string
- `REDIS_URL` — Redis for caching
- `CELERY_BROKER_URL` — Redis for task queue
- `PHISHTANK_API_KEY` — PhishTank API access
- `URLHAUS_AUTH_KEY` — URLHaus API access
- `UPLOAD_MAX_SIZE_MB` — File upload limit
- `RATE_LIMIT_DEFAULT` — API rate limiting

## Quick Start

```bash
# Clone and configure
cp .env.example .env
# Edit .env with your API keys

# Start all services
docker compose up -d

# Verify health
curl http://localhost/api/v1/health
```

## Scaling

- Add more Celery workers: `docker compose up -d --scale celery-worker=3`
- PostgreSQL can be replaced with managed service (RDS, Cloud SQL)
- Redis can be replaced with ElastiCache or Memorystore
