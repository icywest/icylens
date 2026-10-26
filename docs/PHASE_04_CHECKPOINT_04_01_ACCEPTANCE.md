# Phase 04 / Checkpoint 04.01 Acceptance

## A. Initial audit

- Start: clean `main` tracking `origin/main`, commit `5c7dcf4`.
- Tags: `v0.1.0`, `v0.2.0`; `v0.3.0` does not exist and was not assumed.
- Baseline: FastAPI, Pydantic v2, HTTPX in the development toolchain, Ruff,
  strict mypy, pytest, branch coverage, and a unified quality gate.
- Phase 03 baseline: 388 tests and 93.91% coverage.
- Health, ingestion, static-analysis, and ML behavior was preserved.
- HTTPX moved from dev-only to runtime dependencies because production code now
  calls NVD; no new package was introduced.

## B. Architecture decisions

The route, service/normalizer, canonical models, provider schemas, and transport
are separate. FastAPI never consumes raw provider JSON. Provider models tolerate
additive fields; public contracts forbid extras. The application owns and closes
one NVD client. NVD limits are independent of ML inference controls.

## C. NVD data contracts

`VulnerabilityRecord 1.0.0` preserves multilingual descriptions, all supplied
CVSS 2.0/3.0/3.1/4.0 metrics, CWE data, recursive CPE logic/ranges, references,
raw status, timestamps, provenance, completeness, and evidence limitations.
Missing data stays absent or empty. Rejected and unknown statuses are honest.

## D. Implementation inventory

Created:

- `apps/api/app/integrations/__init__.py`
- `apps/api/app/integrations/nvd/__init__.py`
- `apps/api/app/integrations/nvd/client.py`
- `apps/api/app/integrations/nvd/schemas.py`
- `apps/api/app/schemas/vulnerability.py`
- `apps/api/app/services/vulnerability_intelligence.py`
- `apps/api/app/api/v1/routes/vulnerabilities.py`
- `apps/api/scripts/nvd_smoke.py`
- `apps/api/tests/test_nvd_integration.py`
- `apps/api/tests/fixtures/nvd_cve_rich_synthetic.json`
- `apps/api/tests/fixtures/nvd_cve_rejected_synthetic.json`
- `docs/NVD_INTEGRATION.md`
- `docs/VULNERABILITY_DATA_CONTRACTS.md`
- `docs/PHASE_04_CHECKPOINT_04_01_ACCEPTANCE.md`

Modified:

- `apps/api/app/core/config.py`
- `apps/api/app/main.py`
- `apps/api/app/api/v1/router.py`
- `apps/api/pyproject.toml`
- `apps/api/.env.example`
- `apps/api/tests/conftest.py`
- `apps/api/tests/test_analysis_contracts.py`
- `apps/api/tests/test_project_security.py`
- `README.md`
- `docs/API_CONTRACTS.md`
- `docs/ARCHITECTURE.md`
- `docs/DEVELOPMENT_LOG.md`

Deleted: none.

## E. Security review

Exact HTTPS allowlisting, verified TLS, disabled redirects, encoded query
parameters, header-only secrets, finite timeouts/retries, capped `Retry-After`,
rolling per-process budget, concurrency limits, bounded decoded streaming,
media-type/JSON/schema validation, sanitized errors, and client cleanup are
implemented. Tests cover SSRF-shaped values, secret handling, status distinctions,
oversized/corrupt responses, redirects, retry exhaustion, and lifecycle closure.

## F. API demonstration

`GET /api/v1/vulnerabilities/CVE-2021-44228` returns a strict record. Synthetic
fixtures are explicitly test-only. A controlled live smoke on 2026-10-25 verified
the matching ID, status `Analyzed`, three CVSS entries, and about 0.42 seconds.

## G. Data integrity

Requested/returned IDs, pagination, and CVSS bucket/version must agree. UTC
publication, modification, and retrieval times remain distinct. English preference
selects provider text only. Omitted root CPE logic remains null. There is no asset
observation, exploitation/sample conclusion, risk score, or invented severity.

## H. Tests

The deterministic suite covers rich, rejected, incomplete, absent, malformed,
unknown-status, multilingual, multi-CVSS, CWE, recursive CPE, pagination/identity
mismatch, exact schema, HTTP security, budgeting, retries, timeouts, secrets, and
cleanup. The checkpoint added 52 focused cases and the complete suite passed all
440 tests.

## I. Quality gate

Executed from `C:\icylens\apps\api` with
`.\.venv\Scripts\python.exe scripts/quality_gate.py`:

- pytest: **440 passed** in 27.26 seconds;
- total statement/branch coverage: **94.25%** (reported as 94%), above the Phase
  03 baseline of 93.91% and the configured 85% threshold;
- Ruff lint: **PASS**;
- Ruff format check: **PASS** (85 files formatted);
- mypy strict: **PASS** (70 source files);
- `pip check`: **PASS**, no broken requirements;
- unified Quality Gate: **PASS**.

## J. Limitations

- Request budgets are per process, not distributed across workers or hosts.
- NVD availability and quotas remain external dependencies.
- No response cache or persistence is implemented.
- Provider fields outside the 04.01 contract, including CISA enrichment, are not
  interpreted even when NVD supplies them.
- CPE applicability is preserved but not evaluated against assets.
- No CISA KEV, FIRST EPSS, scanning, exploitation, or risk prioritization exists.

## K. Final decision

The initial implementation passed its automated gate but an independent review
subsequently found that HTTPX buffered/decompressed the complete response before
the application limit. Checkpoint 04.01.1 corrects that acceptance-blocking defect
with true streaming and instrumented early-abort tests. The 04.01.1 Quality Gate
passed with 462 tests and 94.42% total coverage; the security review marks all
acceptance-blocking findings fixed. **Phase 04.01 is accepted and may close.**

## L. Version-control handoff

No `git add`, commit, tag, or push was performed. Suggested commits:

1. `build(api): promote httpx to runtime dependency` — `apps/api/pyproject.toml`
2. `feat(vulnerability): add canonical CVE data contracts` — schema/provider models
3. `feat(nvd): add secure bounded CVE API client` — integration/config/env/smoke CLI
4. `feat(api): expose typed vulnerability lookup endpoint` — service/route/lifecycle
5. `test(nvd): cover contracts transport security and normalization` — API tests/fixtures
6. `docs(nvd): document integration contracts and acceptance` — README/docs files

Use `git status --short` for the exact final list before selectively staging.

## M. Next checkpoint

Phase 04 / Checkpoint 04.02 — CVSS, CWE & CPE Normalization. It was not implemented.

