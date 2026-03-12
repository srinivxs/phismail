# PhisMail — Threat Intelligence Design

## Overview

PhisMail queries three threat intelligence feeds concurrently during each analysis to check if submitted URLs/domains are known-malicious.

## Feed Integration

| Feed | Type | Auth | Endpoint |
|---|---|---|---|
| OpenPhish | Community feed (txt) | None | `https://openphish.com/feed.txt` |
| PhishTank | API lookup | API Key | `https://checkurl.phishtank.com/checkurl/` |
| URLHaus | API lookup | Auth-Key (optional) | `https://urlhaus-api.abuse.ch/v1/url/` |

## Query Strategy

1. **Concurrent Execution** — All 3 feeds queried via `asyncio.gather()` with `return_exceptions=True`
2. **Timeout** — 3 second per-feed timeout to prevent pipeline stalls
3. **Graceful Degradation** — Individual feed failures don't block the pipeline
4. **Confidence Scoring** — `match_count / 3.0` (0.33 = one feed, 0.67 = two, 1.0 = all three)

## Caching

- **Key Format**: `threat_lookup:{url}`
- **TTL**: 24 hours (configurable via `CACHE_TTL_THREAT_LOOKUP`)
- **Storage**: Redis

## Result Schema

```json
{
  "openphish_match": true,
  "phishtank_match": false,
  "urlhaus_match": true,
  "domain_blacklisted": true,
  "confidence_score": 0.67,
  "matches": [
    {"source": "openphish", "url": "..."},
    {"source": "urlhaus", "url": "...", "data": {"threat": "phishing", "tags": [...]}}
  ]
}
```
