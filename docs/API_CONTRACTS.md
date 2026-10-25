# iCYLENS API Contracts — Baseline 0.1.0

The machine-readable source of truth is the generated OpenAPI document at
`/openapi.json`. Swagger UI is available at `/docs` and ReDoc at `/redoc`.
This document summarizes the Phase 01 surface; it does not add or promise
future endpoints.

## GET `/api/v1/health/`

Reports that the API process is operational.

Request body: none.

Successful response: HTTP 200 using the `HealthResponse` model with JSON
fields:

| Field | Type | Meaning |
|---|---|---|
| `status` | string | Current value is `healthy`. |
| `service` | string | Configured application name. |
| `version` | string | Configured application version. |
| `message` | string | Human-readable operational message. |

Example:

```json
{
  "status": "healthy",
  "service": "iCYLENS API",
  "version": "0.1.0",
  "message": "iCYLENS backend is operational"
}
```

This endpoint confirms process-level availability only. It does not assess a
database, analysis engine, external dependency, or overall platform security.

## POST `/api/v1/analyses/validate`

Validates educational analysis-request metadata and returns the validated
object. It does not upload, open, execute, persist, or analyze a file.

Request and successful response schema: `AnalysisRequest`.

| Field | Type | Required | Rules |
|---|---|---|---|
| `filename` | string | Yes | Length 1–255 characters; printable characters only; no `/` or `\` path separators; not `.` or `..`. |
| `mode` | string | No | `static` or `educational`; defaults to `static`. |

Unexpected fields are forbidden. The filename is validated metadata only: the
server does not open, resolve, or persist it. Phase 02 must not use this
client-supplied value as a filesystem path; it must generate server-side
storage names and enforce byte-size limits.

Successful request:

```json
{
  "filename": "invoice_update.exe",
  "mode": "static"
}
```

Successful response: HTTP 200 with the same validated fields.

Validation failure: HTTP 422 using FastAPI's standard validation-error
response. Failures include an empty/oversized filename, unsafe filename,
unsupported mode, unexpected field, missing field, malformed JSON, incompatible
content type, or incompatible field type.

## Available Pydantic models

- `HealthResponse`: current health endpoint response contract.
- `AnalysisRequest`: current HTTP input/echo-output contract.
- `AnalysisIndicator`: descriptive indicator with source engine and severity.
- `EngineResult`: one engine's status and indicators; currently not returned
  by an endpoint.
- `AnalysisResult`: verdict, optional 0–100 risk score, and engine results;
  currently not returned by an endpoint.
- `AnalysisResponse`: future analysis identity, lifecycle timestamps, status,
  and optional result; currently not returned by an endpoint.
- `AnalysisStatus`, `ThreatVerdict`, and `AnalysisEngine`: shared string enums
  used by those contracts.

These are typed API/data contracts, not database models. Models not currently
referenced by an endpoint remain preparatory and may be reconciled with real
engine behavior in later phases.

## Phase 01 limitations

- There is no threat-analysis execution endpoint.
- There is no multipart upload or file storage.
- There are no persisted analysis records or job queue.
- There is no authentication or authorization.
- Swagger and ReDoc remain enabled in every environment.
- The health response does not validate downstream dependencies.
