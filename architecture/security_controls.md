# PhisMail — Security Controls

## API Security

| Control | Implementation | Config |
|---|---|---|
| Rate Limiting | slowapi (leaky bucket) | `RATE_LIMIT_DEFAULT` |
| CORS | FastAPI CORSMiddleware | `CORS_ORIGINS` |
| File Validation | Size + MIME type check | `UPLOAD_MAX_SIZE_MB`, `ALLOWED_MIME_TYPES` |
| Input Sanitization | Pydantic model validation | All API schemas |

## Attachment Handling

- **Metadata-only analysis** — attachments are NEVER executed
- File hashes (SHA256) computed for dedup and IOC export
- Double extension detection (e.g., `invoice.pdf.exe`)
- MIME type mismatch detection
- Dangerous extensions flagged: `.exe`, `.bat`, `.cmd`, `.scr`, `.vbs`, `.js`, `.ps1`, `.docm`, `.xlsm`

## Deduplication

- SHA256 hash of email file bytes
- Normalized URL hash (lowercased, trailing slash stripped)
- Prevents re-analysis of identical artifacts

## Audit Trail

- `AuditLog` table records every pipeline event:
  - `pipeline_started`, `pipeline_completed`, `pipeline_failed`
  - Actor, timestamp, detail, IP address
- Enables forensic review of all system actions

## Observability

| Layer | Tool | Metrics |
|---|---|---|
| API | Prometheus + `prometheus_client` | Request count, latency, error rate |
| Pipeline | structlog (JSON) | Event-based structured logging |
| Workers | Celery events | Task completion, queue depth |

## Threat Intelligence Safety

- All external API calls have 3-second timeouts
- Individual feed failures don't block pipeline (graceful degradation)
- API keys stored in environment variables, never in code
