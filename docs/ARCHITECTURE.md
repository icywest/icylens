# iCYLENS Backend Architecture

## System overview

iCYLENS `0.1.0` currently provides a Python 3.12/3.13 backend foundation. The
implemented system is intentionally small: FastAPI exposes versioned HTTP
routes, Pydantic defines request and response contracts, and
`pydantic-settings` supplies typed configuration. There are no analysis
engines, databases, file-processing pipelines, or external service clients in
Phase 01.

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
`services` and `engines` remain empty namespaces so future business logic does
not need to be placed in route handlers.

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

Phase 02 may introduce a Static Analysis Engine under `app/engines`, with
orchestration under `app/services`. Later phases may add Machine Learning,
Vulnerability Intelligence, Behavioral Analysis, and Correlation engines.
Their results can map to the existing `EngineResult` and `AnalysisResult`
contracts after those contracts are reviewed against real requirements.

Phase 02 must treat any client-supplied filename as untrusted metadata only:
use server-generated storage names, enforce maximum bytes and format allowlists,
reject or handle NUL/control characters, avoid following symlinks without
policy, operate in a temporary location with cleanup, and never execute
uploaded content. Authentication, authorization, resource limits, timeouts,
and sandboxing remain out of scope for Phase 01 but should be addressed before
processing untrusted files.

An Astro frontend may eventually consume the FastAPI OpenAPI contract. It is
not present, and no CORS policy has been introduced. Likewise, the placeholder
engine names in enums do not imply that any engine is operational.
