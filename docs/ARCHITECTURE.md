# iCYLENS Backend Architecture

## System overview

iCYLENS `0.1.0` currently provides a Python 3.12/3.13 backend foundation and a
bounded static-analysis pipeline. FastAPI exposes versioned HTTP routes,
Pydantic defines request and response contracts, and `pydantic-settings`
supplies typed configuration. Static engines operate incrementally; there are
no databases, durable file stores, dynamic analyzers, or external service
clients.

The backend lives in `apps/api`:

```text
apps/api/
├── app/
│   ├── main.py                 # Application factory and ASGI app
│   ├── api/v1/                 # Versioned routers and HTTP handlers
│   ├── core/                   # Settings and logging
│   ├── schemas/                # Pydantic HTTP/data contracts
│   │   ├── health.py           # Health endpoint response contract
│   │   ├── analysis.py         # Analysis request/result contracts
│   │   └── common.py           # Shared enums
│   ├── services/               # Reserved for business orchestration
│   └── engines/                # Reserved for analysis implementations
├── scripts/quality_gate.py     # Local quality-gate orchestrator
├── tests/                      # Unit, integration, contract, security tests
├── .env.example
└── pyproject.toml
```

## Implemented layers

### Application factory

`app.main.create_app()` builds the FastAPI application. It receives an
optional `Settings` instance for deterministic tests and otherwise uses the
cached environment-aware configuration. The module-level `app` is the ASGI
entry point expected by Uvicorn.

Importing the module constructs the ASGI application and configures the
project logger, but does not open network ports, access a database, process
files, or call external services.

### HTTP routing

`app.api.v1.router` assembles the Health and Analyses routers. `main.py`
registers that router once using the configured `/api/v1` prefix. Route
handlers deal only with HTTP input and output; the validation endpoint does
not invoke business or analysis logic. Health returns the explicit
`HealthResponse` model so its OpenAPI contract is typed rather than a generic
string map.

### Configuration and logging

`app.core.config.Settings` validates application name, version, environment,
debug mode, API prefix, and log level. Operating-system variables with the
`ICYLENS_` prefix override `.env`, which overrides safe defaults. Production
rejects debug mode.

`app.core.logging` configures only the `icylens` logger with a readable
timestamped format and avoids duplicate handlers. It does not replace or
disable Uvicorn logging.

### Contracts

`app.schemas` contains the health response, shared enums, and analysis-related
Pydantic models. These models are transport contracts, not persistence records
or engine implementations. `AnalysisRequest` rejects control characters, path
separators, and the special path components `.` and `..`; this is input
hardening, not file access. The current HTTP surface is documented in
[`API_CONTRACTS.md`](API_CONTRACTS.md).

## Dependency direction

The current dependency flow is intentionally one-way:

```text
main → v1 router → route modules → schemas → shared enums
  └──────────────→ core settings/logging
```

No circular application imports were found during Phase 01 acceptance.
`services` now coordinates resource lifecycle, while `engines.static` contains
deterministic byte processing and keeps business logic outside route handlers.

## Testing and quality

The suite distinguishes unit, integration, contract, and security tests with
pytest markers. Shared fixtures override every supported setting before
application imports, assert that new settings cannot silently escape that
override, inject testing settings, and clear the settings cache between tests.
Tests use `TestClient`; they require no database, internet connection, or
listening port. The Phase 01 audit expanded negative contract coverage and
recorded 57 tests with 100% statement and branch coverage; evidence and
residual risks are in [`PHASE_01_AUDIT_REPORT.md`](PHASE_01_AUDIT_REPORT.md).

`scripts/quality_gate.py` runs:

1. Ruff lint.
2. Ruff format verification.
3. Strict mypy validation for `app` and `scripts`.
4. Pytest with statement and branch coverage and an 85% floor.
5. `pip check`.

The script uses the active Python interpreter, avoids shell-specific command
execution, and returns a nonzero status when a mandatory check fails.

## Planned integrations—not implemented

Phase 02 now contains bounded ingestion and fingerprinting under `app/engines`
with lifecycle orchestration under `app/services`. Later phases may add Machine Learning,
Vulnerability Intelligence, Behavioral Analysis, and Correlation engines.
Their results can map to the existing `EngineResult` and `AnalysisResult`
contracts after those contracts are reviewed against real requirements.

Client-supplied filenames remain untrusted metadata only. Current code enforces
maximum bytes, rejects NUL/control characters and path separators, performs no
application storage, and never executes uploaded content. Authentication,
authorization, deployment resource limits, interrupting timeouts, and
sandboxing remain outside this checkpoint.

An Astro frontend may eventually consume the FastAPI OpenAPI contract. It is
not present, and no CORS policy has been introduced. Likewise, the placeholder
engine names in enums do not imply that any engine is operational.

## Phase 02 Checkpoint 01 architecture

The v1 router now also registers `api/v1/routes/uploads.py`.
`schemas/upload.py` defines the typed response, while
`services/ingestion.py` owns filename validation, bounded reading, byte-limit
enforcement, operation-ID generation, and cleanup. The route owns only HTTP
binding and known-error-to-status mapping. `Settings.MAX_UPLOAD_BYTES` extends
the existing settings instance; no second loader or settings singleton exists.

The service reads no more than 64 KiB per operation and stops after observing
one byte beyond the configured ceiling. It closes `UploadFile` in a `finally`
block. It never executes, deserializes, logs, sends, or writes uploaded bytes.
The original filename remains untrusted metadata and is never a filesystem
path. No application-managed payload survives the request.

FastAPI/Starlette parses multipart content before calling the route. In the
validated Starlette 1.10 environment, file parts use a spooled temporary file
with a 1 MiB in-memory threshold; Starlette owns parser-error cleanup, and the
service explicitly closes the resulting upload on normal and service-error
paths. This framework-managed spool is not application persistence. The 10 MiB
service limit does not cap the complete HTTP body before parsing, and parser
metadata/other parts consume resources too.

Before public exposure, deployment infrastructure must add a whole-request
size cap, concurrency/rate limits, interrupting timeouts, process memory/CPU
limits, and temporary-storage quotas. Future format parsers will introduce new
attack surfaces and require their own limits. Checkpoint 02.02 can compute
SHA-256 by updating a hash object for each already bounded chunk before the
chunk is discarded; no second full-file buffer is required.

## Phase 02 Checkpoint 02 architecture

`api/v1/routes/fingerprints.py` exposes a separate endpoint so the established
upload response remains unchanged. Both endpoints call the same private
ingestion read loop. Upload ingestion supplies no chunk consumer; fingerprint
ingestion supplies `FingerprintAccumulator.update`. Consequently, hashing,
size measurement, and prefix collection occur during one application-level
read pass with the same 64 KiB and configured maximum-size controls.

`engines/static/fingerprint.py` owns incremental SHA-256, the bounded 4 KiB
prefix, extension mapping, and consistency rules. `signatures.py` owns a small
explicit magic registry and bounded PE pointer validation. The typed response
is isolated in `schemas/fingerprint.py`; it contains no malware verdict, score,
or future ML contract.

Only leading magic is recognized. A polyglot is labeled by the first supported
leading signature, ZIP containers are not opened, PE is only a candidate, and
no structure is declared valid or safe. The fixed 4 KiB prefix adds bounded
application memory beyond hashing state and a 64 KiB read chunk. Existing
multipart pre-buffering/spooling, whole-request, concurrency, timeout, and
temporary-storage limitations remain unchanged from Checkpoint 02.01.

The digest and format evidence can become deterministic inputs and labels for
later feature pipelines or ML datasets. They must be combined with provenance,
quality controls, and future features; neither hashes nor extensions are
malware labels.

## Phase 02 Checkpoint 03 architecture

`services.ingestion.consume_upload` now owns validation, the single 64 KiB
read loop, and unconditional resource cleanup. Its optional synchronous chunk
callback is the minimal observer boundary shared by upload, fingerprint, and
content-inspection services. It does not expose FastAPI inside analytical
engines and does not buffer the complete payload.

`services.content_inspection` composes three incremental consumers:

1. `FingerprintAccumulator` for SHA-256, size, and the 4 KiB signature prefix.
2. `EntropyAccumulator` for a fixed 256-bin byte-frequency histogram.
3. `PrintableStringExtractor` for cross-chunk ASCII state and bounded previews.

After EOF, the service finalizes string state and inspects only the bounded
retained subset. Indicator regular expressions use finite character classes
and explicit maximum lengths; literal command matching is non-recursive.
Duplicate ID/evidence pairs are suppressed and output is capped. URL parsing
is local only and malformed candidates fall back to redacted evidence.

Default retained inspection memory is bounded by 100 x 256 string characters,
100 indicators with evidence capped at 96 characters, the 256-counter entropy
histogram, the 4 KiB signature prefix, and one 64 KiB read chunk. Configured
upper bounds remain finite. Time is O(n) for byte histogram/string extraction,
plus bounded post-processing of retained text.

The response intentionally excludes raw extracted strings. It exposes exact
observed and retained counts, truncation flags, redacted evidence, and original
byte offsets for reported patterns. Evidence exists to support later detection
engineering and feature-vector construction; it is not a verdict or training
label by itself.

Starlette still parses/spools multipart content before application processing.
Application bounds do not replace proxy body limits, authentication,
authorization, concurrency/rate controls, interrupting timeouts, process
limits, or temporary-storage quotas.

## Phase 02 Checkpoint 04 architecture

`api/v1/routes/static_analyses.py` exposes
`POST /api/v1/static-analyses/`. The route binds multipart input, supplies the
central settings, maps known ingestion failures, and converts unexpected
failures to a content-free 500 response. It does not contain extraction logic.

`services/static_analysis.py` is the orchestration boundary. It creates the
synchronous operation identity and aware UTC timestamps, delegates exactly
once to `services.content_inspection.inspect_content`, and maps that result to
`StaticAnalysisResponse`. The existing inspection service remains the single
pipeline owner: its callback sends every accepted chunk to fingerprint,
signature-prefix, entropy, and printable-string accumulators before bounded
indicator matching. The orchestrator never rereads the upload and never
reconstructs those engines.

```text
multipart UploadFile
  -> consume_upload (validation, 64 KiB bounded reads, finally-close)
     -> one callback -> SHA-256 + signature prefix + histogram + ASCII runs
  -> bounded indicator matching over retained string previews
  -> content-inspection result
  -> static-analysis adapter (identity, timestamps, consistency, limitations)
  -> typed unified response (discarded, not persisted)
```

Engines extract deterministic observations; services coordinate lifecycle and
compose those observations into a use-case response. Keeping extraction apart
from interpretation prevents entropy, extensions, or textual patterns from
becoming unsupported verdicts. Indicator `source`, byte `offset`, redacted
`evidence`, and truncation flags retain provenance and make bounded results
explainable without exposing raw strings.

The preparatory `AnalysisResult` model was not reused because it structurally
requires a threat verdict and exposes a risk-score concept unsupported by this
checkpoint. `StaticAnalysisResponse` instead has a literal `completed` process
status and no verdict or score. Future ML or CVE services can consume the same
typed evidence or add separately sourced observations, but are not implemented
and must not reinterpret this report as a label.

Residual controls remain deployment concerns: Starlette may spool multipart
parts before the application limit runs, and the 10 MiB file ceiling is not a
whole-request, concurrency, CPU-time, memory, or temporary-storage defense.

## Phase 02 Checkpoint 05 lifecycle semantics

The static-analysis endpoint remains synchronous and deliberately has no
state machine. Request parsing and filename validation precede the shared
bounded read; successful extraction and report assembly produce the only
response state, `completed`. Validation, size, multipart, or processing errors
produce HTTP errors and no analysis resource. UUIDs identify individual
operations for correlation only and cannot be retrieved later.

`StaticAnalysisResponse` now enforces the invariants that cross component
boundaries: both timestamps must be aware UTC values, completion cannot precede
creation, and fingerprint and entropy byte counts must agree. Existing field
types continue to constrain UUID, lowercase SHA-256, entropy, literals, and raw
string non-exposure. Static report models and reused content-evidence models
forbid unknown fields so unsupported evidence cannot silently enter a report.
Successful JSON remains backward compatible.

The ingestion service continues to own unconditional `UploadFile` cleanup.
Known upload exceptions cross the service boundary and are mapped by the route
to 413 or 422. Unexpected exceptions become a generic 500; only their class is
logged, without exception text, stack data, extracted strings, or bytes.

An asynchronous design would be a separate future boundary: a durable job
record could own queued/processing/failed states, a worker could invoke the
same bounded feature pipeline, and retrieval could expose a persisted report.
None of those semantics are simulated by the current endpoint. An Astro client
can use generated OpenAPI types now, submit multipart data, branch on HTTP
status, and render evidence plus limitations from a completed response.
