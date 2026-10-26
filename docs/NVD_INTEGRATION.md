# NVD CVE API 2.0 Integration

Phase 04 / Checkpoint 04.01 adds a read-only integration with the official NIST
National Vulnerability Database endpoint:

`https://services.nvd.nist.gov/rest/json/cves/2.0`

Only point queries are implemented: `?cveId=CVE-YYYY-NNNN`. The client does not
accept a URL, host, scheme, or path from callers. The route is therefore not a
generic proxy and cannot request an arbitrary network resource.

## Runtime flow

```text
GET /api/v1/vulnerabilities/{cve_id}
  -> strict path validation
  -> VulnerabilityIntelligenceService
  -> bounded NVDClient request
  -> NVDResponse provider validation
  -> canonical normalization and identity check
  -> VulnerabilityRecord 1.0.0
```

Provider models tolerate additive NVD fields (`extra="ignore"`) so upstream
growth does not leak into the public contract. Required structures and values
used by the normalizer remain validated. iCYLENS-owned public models use
`extra="forbid"`.

## Configuration

All variables use the `ICYLENS_` prefix:

| Variable | Default | Purpose |
| --- | ---: | --- |
| `NVD_API_KEY` | empty | Optional NVD key, sent only in the `apiKey` header |
| `NVD_TIMEOUT_SECONDS` | 10 | HTTPX connect/read/write/pool timeout per phase |
| `NVD_TOTAL_DEADLINE_SECONDS` | 45 | Total operation deadline, including capacity and retries |
| `NVD_MAX_RESPONSE_BYTES` | 2 MiB | Maximum decoded response body |
| `NVD_MAX_CONCURRENCY` | 2 | Concurrent NVD operations in this process |
| `NVD_REQUESTS_PER_WINDOW` | 5 | Per-process rolling-window budget |
| `NVD_RATE_WINDOW_SECONDS` | 30 | Rolling-window duration |
| `NVD_MAX_RETRIES` | 2 | Retries after the first attempt |
| `NVD_BACKOFF_SECONDS` | 0.5 | Exponential-backoff base plus jitter |
| `NVD_MAX_RETRY_AFTER_SECONDS` | 10 | Maximum accepted delay/backoff |

Defaults are deliberately conservative. NVD limits and guidance can change;
operators must consult `https://nvd.nist.gov/developers/start-here` before
changing the budget. A key does not automatically raise the configured budget.
The limiter is local to one process; multiple workers do not share state.

Set a key only in the process environment or a local uncommitted `.env`:

```powershell
$env:ICYLENS_NVD_API_KEY = "value-from-nvd"
```

The key is a Pydantic `SecretStr`, never a query parameter, response field, or log
value. The committed `.env.example` contains an empty placeholder only.

## HTTP security and resource controls

- Exact HTTPS scheme, host, port, and path are allowlisted.
- TLS verification is explicit, redirects are disabled, and `trust_env=False`
  prevents implicit proxy and CA-bundle configuration from environment variables.
- HTTPX encodes query parameters after the CVE ID is validated.
- Connection concurrency and rolling requests are bounded per process.
- 429, 5xx, timeout, and transport failures have distinct typed behavior.
- Retries are finite. `Retry-After` seconds or HTTP dates are capped; otherwise
  exponential backoff with jitter is used.
- 403 is not retried. Provider 404 and an empty valid result both become not found.
- Requests use `send(stream=True)`: HTTPX does not pre-buffer the response.
  `Content-Length` is only an early check. Decoded chunks from `aiter_bytes()` are
  counted during streaming, so gzip/deflate expansion is bounded before JSON
  parsing. Reading stops immediately after the first chunk that crosses the limit.
- The application chunk size and transport/decoder buffers create bounded local
  overhead beyond the configured body limit; the limit is not an exact bound on
  total process memory. The retained application body is not copied before
  `json.loads()`.
- An `asyncio.timeout()` deadline surrounds semaphore wait, rate-budget check,
  HTTP requests, response reading, retries, backoff, parsing, and validation.
  Synchronous parsing cannot be preempted mid-instruction, but elapsed time is
  checked before and after synchronous phases and mapped to HTTP 504.
- HTML, invalid media types/JSON/schema, redirects, interrupted bodies, oversized
  bodies, and inconsistent pagination or identity are rejected.
- FastAPI owns one client and closes it during application shutdown.

NVD payloads must declare `format="NVD_CVE"` and `version="2.0"`. Missing or
contradictory contract metadata is rejected. The optional provider-generation
`timestamp` is normalized to UTC as `provider_generated_at`, independently from
iCYLENS `retrieved_at` and the CVE record's `lastModified` value.

The client never logs response bodies, request headers, secret-bearing URLs, or
provider exception messages.

## Error mapping

| Condition | HTTP |
| --- | ---: |
| Invalid path contract | 422, or 404 when routing rejects the path |
| Valid response with no record / provider 404 | 404 |
| Local budget or upstream rate limit | 429 |
| Invalid, oversized, or inconsistent response | 502 |
| Denial, transport failure, or exhausted 5xx retries | 503 |
| Provider timeout | 504 |
| Unexpected internal failure | 500 with generic detail |

## Verification

Automated tests are offline and use `httpx.MockTransport` plus explicitly
synthetic fixtures. To make one optional live request:

```powershell
cd C:\icylens\apps\api
.\.venv\Scripts\python.exe scripts\nvd_smoke.py CVE-2021-44228
```

The command disables retries, so one invocation performs at most one request. On
2026-10-25, after the 04.01.1 streaming hardening, it returned `LIVE VERIFIED`,
matching ID, status `Analyzed`, and three CVSS metric entries in approximately
0.59 seconds. Provider availability is not
part of the deterministic quality gate.

