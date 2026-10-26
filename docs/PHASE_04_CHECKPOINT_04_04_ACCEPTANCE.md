# Phase 04 / Checkpoint 04.04 acceptance

Status: PASS.

## Scope delivered

- Strict FIRST envelope and record contracts with exact decimal handling.
- Fixed-host HTTPS streaming client with decoded-byte limit, total deadline,
  bounded concurrency, local request budget, finite retries, capped delays,
  redirect rejection, and deterministic cleanup.
- Canonical provenance, explicit score absence, UTC retrieval time, score date,
  and configurable current/stale/historical classification.
- Bounded process-local TTL/LRU cache with same-CVE request coalescing and no
  failure caching.
- Typed single-CVE FastAPI endpoint and sanitized error taxonomy.
- Offline fixtures and adversarial unit, contract, security, cache, and API
  tests; a separate one-call live smoke script.

## Acceptance boundaries

The implementation does not add bulk/catalog ingestion, CSV history, time
series, CPE linkage, ML training, active scanning, exploit execution, automatic
patching, malware conclusions, or a combined NVD/KEV/EPSS score. API v1 is not
represented as an EPSS model version. A missing score is not represented as
zero. Percentile is not represented as exploitation probability.

## Acceptance evidence

- Baseline before implementation: 555 tests, 93.26% branch coverage, Ruff,
  strict mypy, `pip check`, and Quality Gate passing.
- Final gate: 621 tests pass, 66 added; 93.15% branch coverage; Ruff lint and
  format, strict mypy over 93 source files, and `pip check` pass.
- Controlled live smoke for `CVE-2021-44228`: validated one matching record;
  score `0.999990000`, percentile `1.000000000`, score date `2026-10-25`, and
  `current` freshness at retrieval `2026-10-26T03:56:02.834205+00:00`. These
  dynamic observations are not test assertions.
- Git operations: none. No add, commit, tag, push, or 04.05 work performed.

The unified gate, controlled live observation, and final repository checks
passed. EPSS remains dated predictive intelligence, not observed exploitation.
