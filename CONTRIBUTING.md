# Contributing to PhisMail

Thank you for your interest in contributing. This document covers the development workflow, code standards, and how to add new detection capabilities.

---

## Development Setup

```bash
git clone https://github.com/srinivxs/phismail.git
cd phismail
cp .env.example .env
docker compose up -d
```

For backend-only development without Docker:

```bash
cd backend
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

---

## Running Tests

```bash
# All unit tests (no external dependencies, ~1s)
python -m pytest tests/unit/ -v

# Single test file
python -m pytest tests/unit/test_risk_scoring.py -v

# Single test
python -m pytest tests/unit/test_risk_scoring.py::TestRiskScoring::test_phishing_verdict -v
```

All tests in `tests/unit/` are pure unit tests. The `conftest.py` auto-mocks `get_settings` and uses SQLite in-memory — no running services needed.

---

## Project Structure

```
backend/app/services/     — one module per analysis capability (stateless, independently testable)
backend/app/workers/      — Celery task orchestration
backend/app/api/          — FastAPI route handlers
frontend/src/components/  — React components
tests/unit/               — unit tests mirroring the services/ structure
```

---

## Adding a New Detection Module

1. Create a new directory under `backend/app/services/your_module/`
2. Add an `__init__.py` and a main analyzer file (e.g., `your_analyzer.py`)
3. Define a result class and an analysis function — keep it stateless
4. Add the new features to `feature_builder.py` (`build_feature_vector`)
5. Add suspicion/trust weights to `rule_engine.py` (`SUSPICION_WEIGHTS` / `TRUST_WEIGHTS`)
6. Add severity entries to `SEVERITY_MAP` and detail strings to `_build_detail()`
7. Call your module in `workers/pipeline.py` at the appropriate stage
8. Write unit tests in `tests/unit/test_your_module.py`

---

## Adding New Risk Scoring Rules

Edit `backend/app/services/risk_scoring/rule_engine.py`:

- **Suspicion signal**: add to `SUSPICION_WEIGHTS` with a float weight
- **Trust signal**: add to `TRUST_WEIGHTS`
- **Content-only signal** (NLP body text): add to `CONTENT_ONLY_FEATURES` so it cannot alone produce a PHISHING verdict
- **Severity**: add to `SEVERITY_MAP` (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW`)
- **Human-readable detail**: add a case to `_build_detail()`

---

## Code Standards

- Python: follow existing module patterns (stateless functions, typed signatures, structlog logging)
- TypeScript: strict mode, no `any`, typed API responses
- Tests: all new services must have corresponding unit tests
- No new external API calls without graceful degradation (try/except with sensible defaults)
- Never execute, decompress, or sandbox attachments — metadata only

---

## Submitting Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes with clear, focused commits
4. Ensure all tests pass: `python -m pytest tests/unit/ -v`
5. Open a pull request with a description of what the change detects or fixes

---

## Reporting Issues

Open a GitHub Issue with:
- A sample `.eml` file or URL that produces an incorrect verdict (anonymise sensitive content)
- The current verdict and score
- The expected verdict and why
