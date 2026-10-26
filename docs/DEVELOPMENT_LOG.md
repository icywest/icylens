# iCYLENS Development Log

## Phase 04 / Checkpoint 04.03: CISA KEV Integration

Added a canonical-only, bounded streaming CISA KEV client; current provider and
canonical contracts; duplicate/count/date validation; immutable atomic snapshots;
freshness-aware indexed lookup; optional nonfatal startup refresh; and read-only
status/lookup endpoints. Offline adversarial tests cover transport, integrity,
lifecycle, and conservative semantics. A single live canonical fetch validated
catalog `2026.10.23` with 1,756 records. No EPSS or unified risk correlation was
introduced.

## Phase 04 / Checkpoint 04.02: CVSS, CWE, and CPE Interpretation

Added lossless CVSS interpretation and deterministic display selection, CWE
special-value classification, a strict declared-inventory contract, structured
CPE 2.3 safe-subset parsing, bounded numeric/SemVer comparison, and a recursive
three-valued applicability engine with evidence traces. Added interpretation and
applicability endpoints with raw-body limits while preserving the base CVE GET
and the hardened NVD client. No scanning, exploitation, persistence, risk score,
KEV, EPSS, or ATT&CK inference was introduced.

## Phase 04 / Checkpoint 04.01.1: NVD HTTP Resource Safety Hardening

Corrected the independent-review finding that `AsyncClient.get()` buffered and
decoded the complete NVD body before the application size check. The integration
now uses true HTTPX streaming, decoded-byte early abort, deterministic response
cleanup, a total operation deadline, explicit `trust_env=False`, strict NVD
format/version validation, and separate provider-generation provenance. Added
instrumented plain/gzip/deflate/interruption tests, concurrency/deadline/cancel
tests, complete CPE semantic assertions, and a FastAPI-to-MockTransport test.
The unified gate passed with 462 tests and 94.42% total coverage; Ruff, strict
mypy, and `pip check` also passed. A controlled live NVD lookup verified the
matching record after hardening. Full evidence is in the 04.01.1 security review.

## Phase 04 / Checkpoint 04.01: NVD CVE Data Contracts & Secure API Integration

Implemented strict canonical CVE contracts, NVD 2.0 provider contracts, secure
bounded HTTP transport, explicit normalization/provenance, a typed lookup route,
synthetic offline fixtures, adversarial tests, and a one-request live smoke CLI.
HTTPX moved from dev-only to runtime; no package was added. Static-analysis and ML
behavior remain unchanged. Final metrics are in
`PHASE_04_CHECKPOINT_04_01_ACCEPTANCE.md`.

## Phase 03 / Checkpoint 03.05: Trusted Local ML Inference

Status: PASS - 388 tests passed (36 focused inference cases added), total
statement/branch coverage reached 93.91%, and Ruff lint/format, strict mypy,
`pip check`, regressions, and the unified Quality Gate passed on 2026-10-25.

- Added disabled-by-default inference/demo settings and bounded non-queuing
  concurrency.
- Added governed synthetic metadata initialization during lifespan, explicit
  lifecycle transitions, rejection, and shutdown revocation.
- Added strict fitted-Pipeline validation for estimator, classes, schema, exact
  23-column preprocessing, probability support, and demo authorization.
- Added single-pass static-analysis reuse through the canonical 14 features to
  one reused in-memory Logistic Regression Pipeline.
- Added strict demo-only response contracts and `POST /api/v1/ml-inferences/`
  with safe 413/422/429/503/500 behavior.
- Added compatibility, lifecycle, probability, cleanup, capacity,
  no-training/no-loading, reproducibility, OpenAPI, regression, and real
  loopback-Uvicorn validation.

No generic model loading, request-time training, test evaluation, SHAP, risk
score, operational verdict, public deployment, external service, or persistent
sample storage was introduced.

## Phase 03 / Checkpoint 03.04: Model Evaluation and Explainability

Status: PASS - 352 tests passed (37 focused evaluation cases added), total
statement/branch coverage reached 94.11%, and Ruff lint/format, strict mypy,
`pip check`, regressions, and the unified Quality Gate passed on 2026-10-25.

- Added strict evaluation schema `1.0.0` with explicit available/unavailable
  metrics, fixed benign/malicious class semantics, and finite-value enforcement.
- Added per-class classification, imbalance, probability, reliability-bin,
  threshold, privacy-conscious aggregate error, and limitation reporting.
- Added deterministic bounded permutation importance over the 14 original
  features through each complete fitted Pipeline.
- Added common-basis comparison and a conservative policy supporting selection,
  insufficient evidence, inconclusive performance, and validation failure.
- Added validation-only in-process evaluation, explicit synthetic abstention,
  staged non-overwriting JSON artifacts, tamper verification, and local CLI.
- Documented calibration limitations, correlated features, serialized-model
  risk, sealed-test custody, and a future one-time final-evaluation protocol.

No test evaluation, hyperparameter tuning, calibration fit, SHAP, local causal
narrative, joblib loading, registry/promotion, inference route, external data,
cloud service, or malware blocking was introduced.

## Phase 03 / Checkpoint 03.03: Reproducible Baseline Training

Status: PASS - 315 tests passed (31 focused training cases added), total
statement/branch coverage reached 95.07%, and Ruff lint/format, strict mypy,
`pip check`, API regressions, and the unified Quality Gate passed on 2026-10-25.

- Added compatible NumPy, scikit-learn, and joblib runtime dependencies for
  Python 3.13 and verified the installed dependency closure.
- Added deterministic 14-input/23-output preprocessing with explicit one-hot
  categories, float booleans, Logistic scaling, and tree passthrough.
- Added bounded Logistic Regression, Random Forest, and HistGradientBoosting
  candidates under a common Pipeline interface with seeded configuration.
- Added repeated dataset integrity/admission checks, synthetic/research modes,
  per-class minimums, training-only fit, validation-only metrics, and sealed
  test behavior.
- Added typed experiment reports with environment/configuration identity,
  exploratory metrics, undefined-metric disclosure, and explicit absence of
  scientific representativeness.
- Added staged non-overwriting joblib export, per-model size/digest checks,
  byte-only verification without deserialization, cleanup, and a local CLI.

No test-set evaluation, hyperparameter search, serving/inference endpoint,
model verdict, external dataset, sample execution, CVE/MITRE integration,
behavioral analysis, or cloud infrastructure was introduced.

## Phase 03 / Checkpoint 03.02: Reproducible Dataset Builder

Status: PASS - 284 tests passed (54 focused pipeline cases added), total
statement/branch coverage reached 96.42%, and Ruff lint/format, strict mypy,
`pip check`, FastAPI regression coverage, and the unified Quality Gate passed
on 2026-10-25.

- Added bounded strict UTF-8 JSON and JSONL imports with byte, record, and line
  limits and no arbitrary deserialization or network behavior.
- Added an auditable builder separating structural validity, governance,
  training eligibility, deterministic SHA-256 deduplication, and acceptance.
- Added fatal conflict detection for labels, label metadata, provenance,
  feature/extraction contracts, record IDs, and existing split assignments.
- Added versioned seeded label-stratified splitting that is invariant to input
  order, respects existing assignments, and rejects infeasible class coverage.
- Added typed manifests, canonical content digests, derived-count verification,
  staged atomic export, non-overwrite behavior, and tamper detection.
- Added a minimal local argparse workflow for validate/build/inspect and
  comprehensive pipeline, security, architecture, and acceptance documentation.

Generated metadata artifacts are ignored by Git. No uploaded binaries, model
training, inference, evaluation, prediction endpoint, external dataset, threat
intelligence, behavioral analysis, database, or cloud storage was introduced.

## Phase 03 / Checkpoint 03.01: ML Dataset Governance & Feature Contracts

Status: PASS - 230 tests passed (22 focused ML contract and validation cases
added), total statement/branch coverage reached 98.87%, and Ruff lint/format,
strict mypy, `pip check`, and the unified Quality Gate passed on 2026-10-25.

- Established feature schema `1.0.0` with a stable 14-field predictive order,
  strict domains, explicit unknown categories, and truncation metadata.
- Added a deterministic, FastAPI-independent adapter over the existing typed
  static report; it performs no upload read, parsing, labeling, or inference.
- Separated sample identity, predictive features, labels, provenance,
  extraction settings, and split assignment in the dataset record contract.
- Added explicit `benign`, `malicious`, and `unknown` labels, conservative
  supervised-training eligibility, and synthetic-label identification.
- Added validation for malformed records, unsupported provenance, exact
  duplicates, conflicting labels, cross-split overlap, duplicate IDs, and
  repeated synthetic templates without silently repairing data.
- Added a safe three-record synthetic fixture and comprehensive governance,
  feature-contract, architecture, and acceptance documentation.

No classifier, fitting, evaluation, prediction endpoint, verdict, score,
external dataset, executable sample, CVE intelligence, MITRE mapping,
behavioral analysis, persistence, or new infrastructure was introduced.

## Phase 02 / Checkpoint 05: Analysis Lifecycle and Contract Hardening

Status: PASS - 208 tests passed (16 focused lifecycle and contract cases
added), statement and branch coverage reached 100%, and Ruff lint/format,
strict mypy, `pip check`, OpenAPI, local runtime checks, and the unified Quality
Gate passed on 2026-10-25.

- Formalized the synchronous lifecycle: successful operations alone return a
  completed report; errors create no queued, processing, failed, or retrievable
  resource.
- Enforced UTC timestamps, chronological completion, cross-section byte-count
  equality, strict report fields, and existing UUID/hash/entropy/raw-string
  constraints at the Pydantic boundary.
- Preserved every successful JSON shape and specialized legacy endpoint.
- Added safe unexpected-error observability using exception type only while
  retaining generic client responses and unconditional upload cleanup.
- Documented the distinct future boundary for persistent background jobs and
  typed Astro consumption without implementing either.

No persistence, GET-by-ID, queue, worker, ML, CVE lookup, score, verdict,
authentication, rate limiting, frontend, or deployment infrastructure was
introduced.

## Phase 02 / Checkpoint 04: Static Analysis Orchestration

Status: PASS - 192 tests passed (17 added for orchestration, API, lifecycle,
security, and regression behavior), statement and branch coverage reached 100%,
and Ruff lint/format, strict mypy, `pip check`, and the unified Quality Gate
passed on 2026-10-25.

- Added `POST /api/v1/static-analyses/` with one typed, unified report.
- Reused the existing content-inspection service as the sole single-pass
  pipeline instead of duplicating engines or reading the upload again.
- Added operation UUIDs, aware UTC lifecycle timestamps, format consistency,
  nested fingerprint/content evidence, source-preserving indicators, explicit
  truncation, and stable limitation codes.
- Kept the legacy analysis schema unchanged because its verdict/risk shape does
  not accurately represent descriptive static evidence.
- Added generic unexpected-failure handling and verified cleanup on success,
  validation failure, oversize rejection, and engine failure.

No verdict, risk score, ML, CVE lookup, MITRE mapping, persistence, background
job, authentication, frontend, network lookup, or content execution was added.

## Phase 02 / Checkpoint 03: Entropy and Content Inspection

Status: PASS - 175 tests passed (43 added across engine, API, configuration,
security, and regression coverage), statement and branch coverage reached 100%,
and Ruff lint/format, strict mypy, `pip check`, and the unified Quality Gate
passed on 2026-10-25.

- Added `POST /api/v1/content-inspections/` with a typed, non-persistent report.
- Added an incremental 256-bin Shannon entropy engine.
- Added cross-chunk printable ASCII extraction with exact observed counts,
  bounded retained previews, original offsets, and explicit truncation state.
- Added bounded informational URL, IPv4, command, executable, and script
  indicators with duplicate suppression and redacted evidence.
- Refactored ingestion cleanup into one shared consumer so upload,
  fingerprinting, and inspection preserve a single bounded read pass.
- Added centralized inspection bounds and deterministic synthetic tests.

Raw extracted strings are not exposed, logged, or persisted. No verdict, risk
score, YARA, ML, CVE intelligence, storage, network lookup, or execution was
introduced.

## Phase 02 / Checkpoint 02: File Fingerprinting

Status: PASS - 132 tests passed (48 new fingerprint tests), statement and branch
coverage reached 100%, and Ruff lint/format, strict mypy, `pip check`, and the
unified Quality Gate passed on 2026-10-25.

- Added `POST /api/v1/fingerprints/` without changing the upload contract.
- Added incremental SHA-256 and actual byte counting to the existing single
  bounded read pass.
- Added explicit PDF, PNG, JPEG, GIF, ZIP, ELF, and bounded PE-candidate magic
  identification with 4 KiB maximum retained signature data.
- Added typed signature evidence and extension consistency states: `match`,
  `mismatch`, and `unknown`.
- Added safe synthetic engine, API, boundary, security, cleanup, and regression
  tests; no live samples or external services are used.

No entropy, strings, YARA, malware classification, ML, CVE correlation,
persistence, database, history, sandbox, or content execution was introduced.

## Phase 02 / Checkpoint 01: Secure File Ingestion

Status: PASS - 84 tests passed (22 upload tests), statement and branch coverage
reached 100%, and Ruff lint/format, strict mypy, `pip check`, and the unified
Quality Gate passed on 2026-10-25.

- Added `POST /api/v1/uploads/` with a typed HTTP 201 response and explicit
  `persisted: false` semantics.
- Added reusable filename validation, configurable 10 MiB maximum size,
  bounded 64 KiB reads, empty/oversize rejection, and deterministic cleanup.
- Declared `python-multipart` as a direct runtime dependency.
- Added functional, adversarial, configuration, cleanup, regression, and
  OpenAPI tests without weakening existing quality settings.
- Documented framework spooling and the residual need for deployment-level
  request, concurrency, timeout, memory, and temporary-storage controls.

No hashing, signature parsing, malware classification, persistence, database,
job queue, authentication, external network integration, or executable content
handling was introduced.

## Phase 01 — Step 04: Backend Configuration & Environment Management

Status: PASS — 29 tests passed, Ruff passed, dependency integrity passed, and
the API was smoke-tested with Uvicorn on the loopback interface.

- Added centralized, typed settings through `pydantic-settings`.
- Added stable `.env` loading with the `ICYLENS_` variable prefix and a safe
  `.env.example` template.
- Added development, testing, and production environment validation;
  production rejects debug mode.
- Integrated application name, version, debug mode, API prefix, and health
  metadata with the shared settings instance.
- Added idempotent standard-library logging for the `icylens` logger without
  changing Uvicorn loggers.
- Added `pyproject.toml` with runtime and `dev` dependency groups.
- Added isolated settings, environment precedence, logging, and regression
  tests.
- Documented local installation, configuration, startup, and quality commands.

No analysis engines, persistence, authentication, file upload, frontend, or
external services were introduced in this checkpoint.

## Phase 01 — Step 05: Automated Testing, Code Quality & Quality Gates

Status: PASS — 34 tests passed, application branch coverage reached 100% with
an enforced 85% floor, and all unified quality gates passed.

- Measured the pre-gate baseline at 29 passing tests and 97% branch coverage.
- Added shared deterministic fixtures and explicit unit, integration,
  contract, and security test markers.
- Added meaningful API-prefix validation and repository safety tests.
- Added pytest-cov with an enforced 85% application branch-coverage floor and
  terminal, HTML, and XML reports.
- Expanded Ruff configuration to include import ordering and selected common
  defect checks, plus formatting verification.
- Adopted strict mypy validation for application and quality-script code.
- Added a cross-platform Python quality gate that uses the current interpreter
  and propagates mandatory-check failures.
- Documented local quality commands and failure interpretation.

No application features, analysis engines, persistence, authentication,
frontend, Docker, or CI/CD workflows were added.

## Phase 01 — Step 06: Foundation Acceptance & Backend Baseline Release

Status: PASS — Phase 01 baseline `0.1.0` accepted on 2026-10-25.

- Re-audited repository structure, import direction, configuration, contracts,
  dependency declarations, tests, generated artifacts, and Git state.
- Re-ran the unified Quality Gate: 34 tests passed, statement and branch
  coverage were 100%, and Ruff, strict mypy, and `pip check` passed.
- Revalidated failure propagation with the safe self-test exit code 7.
- Verified Health, validation, Swagger, ReDoc, and OpenAPI through both
  TestClient and a real Uvicorn process bound to `127.0.0.1:8765`.
- Validated editable `.[dev]` installation and the full Quality Gate in a
  disposable Python 3.13 virtual environment.
- Added formal architecture, API-contract, and Phase 01 acceptance documents.
- Recorded known limitations, pending technical decisions, and Phase 02
  readiness without implementing Phase 02 functionality.

Repository release actions remain pending explicit authorization: branch
`master` has no commits, all baseline files are untracked, and no version tag
exists. Suggested commit message:
`chore(backend): establish phase 01 foundation baseline`. Suggested optional
annotated tag: `v0.1.0`.

## Phase 01 — Comprehensive Technical Audit & Hardening

Status: PASS — Audit completed; Phase 01 remains accepted with tightened
contracts and documentation.

- Audited repository discovery, architecture, code quality, API contracts,
  configuration, security, logging, testing, quality gate, coverage/static
  analysis, dependency reproducibility, runtime validation, and documentation.
- Verified Quality Gate and clean-environment installation: 57 tests passed,
  100% statement and branch coverage, Ruff clean, mypy strict clean,
  `pip check` clean. Failure propagation revalidated (exit code 7).
- Runtime validated via TestClient and Uvicorn on `127.0.0.1:8765` (health,
  docs, redoc, openapi, validate happy path and invalid inputs).
- Dependency vulnerability scan (`pip-audit`) in a disposable clean venv found
  no known vulnerabilities in the declared closure.
- Added explicit `HealthResponse` schema and typed health response.
- Hardened `AnalysisRequest.filename`: rejects control characters, path
  separators (`/`, `\`), and `.`/`..`; preserves printable Unicode and spaces.
- Strengthened test environment isolation (enforces coverage of all supported
  `Settings` fields), expanded contract/config/security tests, and corrected
  minor `.gitignore`/documentation drift.
- Documented filename-as-untrusted-metadata policy for Phase 02 and updated
  architecture/API/README/acceptance documents.

No commits, tags, or pushes created. All changes are local and reversible.

## Phase 04 / Checkpoint 04.04 — FIRST EPSS integration

Implemented a fixed-endpoint, bounded streaming FIRST client; strict decimal
and envelope contracts; canonical provenance and freshness; explicit
`not_scored`; a bounded in-memory TTL/LRU cache; and the typed single-CVE EPSS
route. Added adversarial offline fixtures/tests, a controlled live smoke script,
configuration documentation, and semantic guidance. No unified scoring, ML,
CPE connection, bulk ingestion, Git release action, or 04.05 work was added.
Final gate measurements are recorded in the checkpoint acceptance report and
handoff.

Final evidence: 621 tests passed (66 added), 93.15% branch coverage, Ruff
lint/format PASS, strict mypy PASS over 93 source files, `pip check` PASS, and
the unified Quality Gate PASS. One controlled live FIRST lookup validated the
requested CVE and returned a score dated 2026-10-25 with current freshness.

## Phase 04 / Checkpoint 04.05 — unified evidence correlation

Added strict unified source and evidence contracts, a bounded correlation
service, GET correlation, and POST declared-inventory assessment. The service
calls NVD and EPSS once in parallel, reads KEV without refresh, reuses existing
CVSS/CWE and CPE logic, isolates typed source failures, and preserves source
timestamps and freshness. No combined score, ML dependency, persistence,
malware conclusion, Git release operation, or 04.06 work was introduced.

Final test and quality measurements are recorded in the checkpoint acceptance
document and implementation handoff.

Final evidence: 685 tests passed (64 added), 93.28% branch coverage, Ruff
lint/format PASS, strict mypy PASS over 97 source files, `pip check` PASS, and
the unified Quality Gate PASS.
