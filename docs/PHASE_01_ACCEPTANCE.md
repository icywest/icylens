# Phase 01 Foundation Acceptance

## Baseline identification

- Project: iCYLENS — Intelligent Cybersecurity Analysis Platform
- Phase: Phase 01 — Backend Foundation
- Baseline version: `0.1.0`
- Acceptance date: 2026-10-25 (reviewed and revalidated by comprehensive audit)
- Decision: PASS, subject to the documented limitations below
- Audit report: [PHASE_01_AUDIT_REPORT.md](PHASE_01_AUDIT_REPORT.md)

This document records the validated foundation against which later backend
changes can be compared.

## Implemented capabilities

- FastAPI application factory and Uvicorn ASGI entry point.
- Versioned `/api/v1` router with Health and request-contract validation.
- Pydantic v2 contracts and shared string enums.
- Explicit `HealthResponse` contract and hardened `AnalysisRequest`
  validation (control characters, path separators, `.`/`..` rejected).
- Typed environment configuration through `pydantic-settings`.
- Development, testing, and production environment values; production rejects
  debug mode.
- Idempotent standard-library logging for the `icylens` logger.
- PEP 621 dependency metadata with runtime and `dev` dependency groups.
- Unit, integration, contract, and repository-security tests.
- Unified lint, format, type, test, coverage, and dependency quality gate.

## Accepted API surface

| Method | Path | Accepted behavior |
|---|---|---|
| GET | `/api/v1/health/` | Returns HTTP 200 with status, name, and version. |
| POST | `/api/v1/analyses/validate` | Valid metadata returns 200; invalid metadata returns 422. |
| GET | `/docs` | Swagger UI returns HTTP 200. |
| GET | `/redoc` | ReDoc returns HTTP 200. |
| GET | `/openapi.json` | OpenAPI document returns HTTP 200. |

The validation endpoint performs no file access, threat detection, record
creation, or analysis. See [`API_CONTRACTS.md`](API_CONTRACTS.md).

## Acceptance evidence

### Automated quality

- Tests: 57 passed, 0 failed (expanded contract and configuration coverage).
- Application statements: 150/150 covered (100%).
- Application branches: 14/14 covered (100%).
- Enforced coverage floor: 85%, passed.
- Ruff lint: passed.
- Ruff format: passed for 23 Python files.
- Strict mypy: passed for 18 application/script files.
- `pip check`: no broken requirements.
- Unified Quality Gate: passed.
- Failure propagation self-test: expected FAIL with exit code 7.

### Configuration

- Defaults, `.env`, operating-system precedence, boolean conversion,
  environment/log-level validation, API-prefix validation, cache isolation,
  and production debug rejection (including via `.env`) are covered by tests.
- Test environment overrides cover every supported `Settings` field and fail
  fast if coverage drifts.
- `.env.example` contains documented non-secret settings only.
- Production with `DEBUG=true` is rejected.

### Runtime

Uvicorn was started on `127.0.0.1:8765`. Health, contract validation,
Swagger, ReDoc, and OpenAPI returned HTTP 200 over a real local socket. Only
the process started for acceptance was stopped. Equivalent endpoint checks
also passed through `TestClient`, including HTTP 422 for invalid metadata.

### Installation

A separate temporary Python 3.13 virtual environment was created. Installing
the backend with `pip install -e ".[dev]"`, importing the application, and
running the complete Quality Gate all succeeded. The environment was removed
after validation.

Dependencies use compatible version ranges, not a lockfile; this validates a
fresh installation on the acceptance date but is not bit-for-bit
reproducibility. The clean environment emitted a non-failing upstream warning
that `fastapi.testclient` may migrate from `httpx` to `httpx2`.

### Security and repository hygiene

- `.env`, `.venv`, caches, coverage outputs, and package metadata are ignored.
- No local `.env` existed during acceptance.
- No credential-like assignment was evident in the inspected project files.
- OpenAPI contained only the intended paths and no credential-like schema
  field names; `HealthResponse` is explicitly typed.
- The documented Uvicorn command binds to localhost only.
- No duplicate application root was found.
- Filename validation blocks control characters, path separators, and `.`/`..`
  without exposing filesystem paths.

These checks are repository hygiene, not a security audit. A targeted
dependency vulnerability scan (`pip-audit`) was run in a disposable clean
virtual environment and found no known vulnerabilities in the declared
closure; the local project distribution was not audited. No penetration test
was performed.

## Known limitations

- No file upload, validation pipeline, static analysis, hashing, entropy,
  signature detection, malware classification, or report persistence exists.
- Machine Learning, CVE intelligence, behavioral analysis, and correlation are
  planned names only.
- No authentication, authorization, database, job queue, frontend, CORS,
  deployment infrastructure, or external observability is implemented.
- Interactive API documentation is still enabled in production.
- Dependency ranges are not locked.
- The repository has no commits: all baseline files remain untracked on branch
  `master`, and no `v0.1.0` tag exists. Release history is therefore not yet
  established.
- The upstream TestClient deprecation warning requires future dependency
  review but does not affect current test outcomes.
- `AnalysisRequest` enforces filename hygiene but does not enforce storage
  policy or resource limits; Phase 02 must treat filenames as untrusted
  metadata and use server-generated names.

## Pending technical decisions

- Select and maintain a dependency-locking strategy.
- Decide when to add CI/CD enforcement for `scripts/quality_gate.py`.
- Decide whether production should expose Swagger/ReDoc.
- Review FastAPI/Starlette's TestClient migration path before changing HTTPX
  dependencies.
- Define Phase 02 file-size limits, accepted input sources, temporary-file
  handling, resource limits, timeouts, cleanup, and safe parser strategy.
- Treat any client-supplied filename as untrusted metadata only; never use it
  for filesystem operations without sanitization and a server-generated name.
- Reconcile preparatory result schemas with evidence from the first real
  static-analysis implementation.
- Consider adding advisory scanning (`pip-audit`/OSV) to CI when network
  access is permitted.

## Phase 02 readiness

Phase 01 is accepted as a stable backend foundation. Phase 02 may begin with
safe static file analysis without execution: input validation, SHA-256,
metadata, Shannon entropy, signature identification, static indicators, and
structured reports. Release version control should be established before or
alongside that work, with explicit user authorization.
