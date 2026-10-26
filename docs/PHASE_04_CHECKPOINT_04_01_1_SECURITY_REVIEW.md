# Phase 04 / Checkpoint 04.01.1 Security Review

## Original finding and root cause

The 04.01 client called `AsyncClient.get()`. HTTPX 0.28.1 implements this through
`send(stream=False)`, which calls `response.aread()` before returning. Therefore
the apparent `aiter_bytes()` limit ran only over an already buffered and decoded
body. A pre-fix in-memory reproduction with a 1 KiB limit consumed all 4 KiB of a
plain stream; a 96-byte gzip body expanded to 64 KiB before rejection.

The old tests supplied pre-built `Response(content=...)` bodies and asserted only
the eventual exception. They did not observe transport consumption and therefore
could not detect the defect.

## Remediation

- `build_request()` plus `send(stream=True)` leaves successful responses open.
- Headers are checked before body iteration.
- `aiter_bytes()` yields decoded data; the application stops on the first chunk
  crossing `NVD_MAX_RESPONSE_BYTES` and closes in `finally`.
- JSON parsing accepts the retained `bytearray`, avoiding an additional body copy.
- HTTPX per-phase timeouts remain; `NVD_TOTAL_DEADLINE_SECONDS` encloses capacity
  wait, rate limiting, requests, retries, backoff, streaming, parsing, and schema
  validation. External `CancelledError` is not converted or suppressed.
- `trust_env=False` disables implicit environment proxies and CA bundles.
- Payload metadata must declare `NVD_CVE`/`2.0`; the optional generation timestamp
  is preserved separately from retrieval and record-modification timestamps.

## Instrumented proof

`InstrumentedStream` records chunks, network bytes, completion, and closure.
Tests prove that oversized plain bodies stop before the remaining chunks, gzip and
deflate limits apply to decoded bytes, an overstated `Content-Length` reads no
body, an understated/absent length cannot bypass the decoded limit, and interrupted
or corrupt compressed streams are typed and closed. Transport and chunk buffers
can temporarily retain additional
data; `NVD_MAX_RESPONSE_BYTES` is a retained decoded-body limit, not an exact
whole-process memory ceiling.

Observed with a 1 KiB limit:

- Plain: 8 chunks available; 3 consumed; 1,536 network bytes consumed; iteration
  incomplete; stream closed.
- Gzip: 96 compressed bytes / 64 KiB decoded; 12 chunks available; 4 consumed;
  32 network bytes consumed; iteration incomplete; stream closed.

Deadline tests cover semaphore wait, slow stream, retry backoff, cancellation,
capacity release, two concurrent operations, a queued excess operation, and retry
budget consumption. A real NVD client with `MockTransport` now runs through the
FastAPI route; incompatible metadata maps to 502.

## Finding disposition

| Finding | Status | Evidence |
| --- | --- | --- |
| NVD-SEC-001 pre-buffered body | Fixed | Instrumented plain/compressed early abort |
| NVD-RES-002 no total deadline | Fixed with documented CPU caveat | Capacity/slow-stream/backoff tests |
| NVD-NET-003 implicit environment trust | Fixed | Constructor assertion for `trust_env=False` |
| NVD-CON-004 unvalidated provider metadata | Fixed | Literal contract and 502 integration test |
| NVD-TST-005 insufficient resource tests | Fixed | Instrumented streams and concurrency suite |
| NVD-DEP-006 no lockfile | Accepted residual risk | No dependency policy change authorized |

## Residual risks

- Rate limiting is per process, not distributed.
- Async deadlines cannot preempt a synchronous CPU instruction; elapsed time is
  checked around parsing/validation.
- HTTP/TLS/decoder internals and one application chunk add memory overhead beyond
  the configured retained-body limit.
- The repository still lacks a lockfile; HTTPX remains constrained to `>=0.28,<1`.
- NVD availability is external, and live smoke is not part of deterministic tests.

## Verification

- Focused NVD integration suite: 74 cases included in the passing full suite.
- Full suite: 462 passed in 29.47 seconds.
- Total statement/branch coverage: 94.42%.
- Ruff lint/format: PASS.
- Mypy strict: PASS, 70 source files.
- `pip check`: PASS.
- Unified Quality Gate: PASS.
- Controlled live smoke: `CVE-2021-44228`, status `Analyzed`, three metrics,
  approximately 0.59 seconds.
- `git diff --check`: PASS.

Decision: **PASS**, subject only to the documented residual risks. Checkpoint
04.01 may close and 04.02 may begin after the requested version-control handoff.
