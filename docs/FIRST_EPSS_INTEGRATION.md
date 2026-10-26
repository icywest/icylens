# FIRST EPSS integration

Checkpoint 04.04 adds one read-only point lookup:

`GET /api/v1/intelligence/epss/{cve_id}`

The only upstream is FIRST's fixed HTTPS endpoint,
`https://api.first.org/data/v1/epss`, with the validated CVE supplied as the
`cve` query parameter. The implementation does not accept a URL, provider
filter, catalog query, CSV download, batch, or historical-series request.

## Flow and trust boundary

```text
FIRST API -> bounded HTTPS stream -> provider schema -> identity check
          -> canonical EPSS result -> bounded process-local cache -> FastAPI
```

`app/integrations/first_epss/client.py` fixes scheme, host, port, and path;
enables certificate verification; disables redirects and environment proxy
inheritance; and uses HTTPX streaming. It checks declared length and counts
decoded bytes incrementally, including gzip expansion. Per-request HTTP
timeouts sit inside a total operation deadline. A semaphore bounds concurrent
requests, a rolling local budget rejects excess work, and retry/backoff and
`Retry-After` are finite and capped. Responses close in `finally`, including
decode errors, interruption, timeout, and cancellation.

The provider envelope requires `status: OK`, `status-code: 200`, a nonempty
API `version` and `access`, consistent `total`/`data`, zero point-query offset,
and no hidden or multiple page results. Each returned record requires a CVE,
finite decimal score and percentile in `[0, 1]`, and a valid date. The service
then requires the returned CVE to match the query exactly. Unknown provider
metadata is ignored for forward compatibility; contradictory known metadata
is rejected.

An empty valid result becomes `status: not_scored`, `score: null`,
`percentile: null`, and `freshness: unavailable`. It is distinct from a
transport failure, an invalid FIRST response, NVD absence, and KEV absence.

## Cache and configuration

The application owns one FIRST client and one service for its lifetime. The
service uses an in-memory TTL/LRU cache keyed by normalized CVE. It caches only
validated `available` and `not_scored` results, coalesces simultaneous requests
for the same CVE, never caches failures, and recomputes freshness on hits.
The cache is bounded, disappears on process restart, and contains public data.

| Setting | Default | Meaning |
|---|---:|---|
| `ICYLENS_EPSS_TIMEOUT_SECONDS` | 10 | HTTPX phase timeout |
| `ICYLENS_EPSS_TOTAL_DEADLINE_SECONDS` | 30 | Whole-operation deadline |
| `ICYLENS_EPSS_MAX_RESPONSE_BYTES` | 262144 | Maximum decoded response bytes |
| `ICYLENS_EPSS_MAX_CONCURRENCY` | 2 | Concurrent upstream operations |
| `ICYLENS_EPSS_REQUESTS_PER_WINDOW` | 60 | Conservative local request budget |
| `ICYLENS_EPSS_RATE_WINDOW_SECONDS` | 60 | Budget window |
| `ICYLENS_EPSS_MAX_RETRIES` | 2 | Additional transient attempts |
| `ICYLENS_EPSS_BACKOFF_SECONDS` | 0.5 | Backoff base |
| `ICYLENS_EPSS_MAX_RETRY_AFTER_SECONDS` | 10 | Delay cap |
| `ICYLENS_EPSS_CACHE_TTL_SECONDS` | 3600 | Cache lifetime |
| `ICYLENS_EPSS_CACHE_MAX_ENTRIES` | 1024 | LRU capacity |
| `ICYLENS_EPSS_CURRENT_MAX_AGE_DAYS` | 1 | Inclusive current threshold |
| `ICYLENS_EPSS_STALE_MAX_AGE_DAYS` | 7 | Inclusive stale threshold |

The local 60-per-minute default is an application safety policy, not a claim
about FIRST's service quota. Consult the current official API reference before
changing traffic policy.

## Error boundary

| Condition | HTTP |
|---|---:|
| Invalid path CVE | 422 |
| Local/provider rate limit | 429 |
| Invalid/corrupt/contradictory provider response | 502 |
| Transport, denial, or exhausted 5xx retries | 503 |
| HTTP/body/total deadline | 504 |
| Unexpected internal failure | 500, sanitized |

HTTP failures are not returned as `temporarily_unavailable` HTTP 200 records.
That canonical status is reserved for a future explicit data contract; current
provider unavailability is an HTTP 503.

Official references: [EPSS](https://www.first.org/epss/),
[data and API guidance](https://www.first.org/epss/data.html), and
[API reference](https://api.first.org/epss).

