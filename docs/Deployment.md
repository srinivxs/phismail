# PhisMail — Deployment Guide

## Prerequisites

- Docker & Docker Compose
- PhishTank API key (optional, for live threat intel)
- URLHaus Auth key (optional)

## Quick Start

```bash
# 1. Clone repository
git clone <repo-url> && cd phismail

# 2. Configure environment
cp .env.example .env
# Edit .env with your API keys and settings

# 3. Start all services
docker compose up -d

# 4. Verify health
curl http://localhost/api/v1/health
```

## Services

| Service | URL | Health Check |
|---|---|---|
| Dashboard | http://localhost | NGINX → Next.js |
| API | http://localhost/api/v1 | `/api/v1/health` |
| PostgreSQL | localhost:5432 | `pg_isready` |
| Redis | localhost:6379 | `redis-cli ping` |

## Environment Variables

See [.env.example](../.env.example) for full list. Key variables:

```env
DATABASE_URL=postgresql://phismail:password@postgres:5432/phismail
REDIS_URL=redis://redis:6379/0
PHISHTANK_API_KEY=your_key_here
URLHAUS_AUTH_KEY=your_key_here
```

## Database Initialization

Database tables are auto-created on first startup via SQLAlchemy `Base.metadata.create_all()`.

## Scaling Workers

```bash
docker compose up -d --scale celery-worker=3
```

## Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f backend
docker compose logs -f celery-worker
```

## Production Considerations

1. **TLS**: Configure NGINX with SSL certificates
2. **Database**: Use managed PostgreSQL (RDS, Cloud SQL)
3. **Redis**: Use managed Redis (ElastiCache, Memorystore)
4. **Secrets**: Use vault or cloud secrets manager
5. **Monitoring**: Connect Prometheus to Grafana dashboards
