# iCYLENS API Contracts — Baseline 0.1.0

## Phase 04.03 CISA KEV intelligence

`GET /api/v1/intelligence/kev/status` always returns public snapshot metadata:
`fresh`, `stale`, `unavailable`, or `never_loaded`, plus optional version,
release/retrieval timestamps, freshness age, and count. It exposes no paths,
secrets, endpoint configuration, stack traces, or refresh control.

`GET /api/v1/intelligence/kev/{cve_id}` returns `KEVLookupResult` 1.0.0. Presence
is `listed`, `not_listed`, or `not_established`; the last is used for a stale
negative. No validated snapshot yields 503, an invalid CVE yields 422, and
unexpected failures yield sanitized 500. A valid fresh negative returns 200
`not_listed` to distinguish a successful catalog query from provider failure.

Both routes are read-only and perform no fetch. `KEVRecord` preserves CISA text,
dates, ransomware status, optional forensic-triage/CWE values, and provenance.

## Phase 04.02 interpretation and applicability

`GET /api/v1/vulnerabilities/{cve_id}/interpretation` returns
`VulnerabilityInterpretation` 1.0.0 with every CVSS metric, display-selection
status/reason, CWE classifications, no applicability result, and explicit
limitations. It uses the same NVD error taxonomy as the base GET.

`POST /api/v1/vulnerabilities/{cve_id}/applicability` accepts an inline-documented
`AssetInventory` 1.0.0 and returns `ApplicabilityAssessment` 1.0.0. The body is
read as a bounded stream before JSON decoding. Invalid inventory is 422 and a
body over `ICYLENS_VULNERABILITY_MAX_INVENTORY_BODY_BYTES` is 413. Provider
404/429/502/503/504 semantics remain intact. Inventories are not persisted.

The original `GET /api/v1/vulnerabilities/{cve_id}` response remains the
canonical source record; its only additive field is optional source weakness
`weakness_type`, and `base_score` can represent source absence as null.

## Phase 04.01 vulnerability lookup

`GET /api/v1/vulnerabilities/{cve_id}` accepts only uppercase IDs matching the
public CVE pattern. It has no body or URL parameter. HTTP 200 returns
`VulnerabilityRecord` 1.0.0. Errors are 404 absent, 422 invalid identifier, 429
capacity, 502 invalid provider response, 503 unavailable, 504 timeout, and a
sanitized 500. See
[`VULNERABILITY_DATA_CONTRACTS.md`](VULNERABILITY_DATA_CONTRACTS.md).

The machine-readable source of truth is the generated OpenAPI document at
`/openapi.json`. Swagger UI is available at `/docs` and ReDoc at `/redoc`.
This document summarizes the accepted Phase 01 surface and the implemented
Phase 02 Checkpoints 02.01-02.04: upload, fingerprint, content inspection, and
unified static analysis.

## POST `/api/v1/ml-inferences/`

Accepts one multipart `file`. It is unavailable unless both
`ICYLENS_ML_INFERENCE_ENABLED` and `ICYLENS_ML_DEMO_MODE_ENABLED` are explicitly
true and lifespan registration succeeds.

Success returns strict `MLInferenceResponse` with inference/analysis UUIDs,
`synthetic_demo`, `demo_only: true`, a binary model label, benign/malicious
probabilities, `probability_calibrated: false`, trusted model provenance, and
five mandatory limitations. The label is model output, not a `safe`, `clean`,
malware verdict, or risk score. No filename, hash, content, extracted string,
source path, or local explanation is returned.

Errors are 413 for upload limit, 422 for empty/invalid input, 429 for full
capacity, 503 for disabled/unavailable inference, and generic 500 for unexpected
failures. Missing/malformed multipart is a client 4xx. The request contains no
model path, artifact, dataset, or candidate field.

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
- `UploadResponse`: successful ingestion-operation metadata; its `persisted`
  field is constrained to `false`.
- `FingerprintResponse`: SHA-256, measured size, leading-signature evidence,
  extension, and typed consistency state.
- `ContentInspectionResponse`: fingerprint identity, entropy summary, bounded
  string-extraction statistics, and redacted informational indicators.
- `StaticAnalysisResponse`: synchronous operation metadata plus composed
  fingerprint, content, indicator, truncation, provenance, and limitation data.

These are typed API/data contracts, not database models. Models not currently
referenced by an endpoint remain preparatory and may be reconciled with real
engine behavior in later phases.

## POST `/api/v1/uploads/`

Validates one untrusted file and discards its bytes. The request media type is
`multipart/form-data` with a required file part named `file`. Success is HTTP
201:

```json
{
  "upload_id": "7b6412eb-b716-4a5e-b959-e456dc25e9f7",
  "filename": "sample.txt",
  "size_bytes": 128,
  "content_type": "text/plain",
  "status": "validated",
  "persisted": false
}
```

`upload_id` identifies this ingestion operation only. `content_type` is
client-declared metadata and may be null or inaccurate; it is not detected truth.
No malware verdict is produced.

| Condition | HTTP | Detail |
|---|---:|---|
| Valid nonempty file at or below the limit | 201 | Typed `UploadResponse` |
| Empty bytes | 422 | File must not be empty |
| Missing `file` part | 422 | FastAPI validation response |
| Invalid filename | 422 | Required, at most 255 printable characters, no path separators, not `.`/`..` |
| More than `ICYLENS_MAX_UPLOAD_BYTES` | 413 | Configured maximum is included in the detail |
| Malformed multipart | 4xx | Parser/client error, normally 400 or 422 depending on the defect |
| Unexpected application failure | 500 | Framework server-error response; no success is fabricated |

The default limit is 10 MiB (10 x 1024 x 1024 bytes). The service uses bounded
64 KiB reads and observes at most one byte beyond the configured limit. It
closes the upload on every service exit and retains no bytes. Starlette may
already have buffered or spooled the part while parsing, so this is not a
complete HTTP request-size defense.

## POST `/api/v1/fingerprints/`

Calculates deterministic identity and limited format evidence without a second
file read or persistence. Input is `multipart/form-data` with one required
`file` part. Success is HTTP 200 using `FingerprintResponse`:

```json
{
  "filename": "document.pdf",
  "sha256": "a lowercase 64-character hexadecimal digest",
  "size_bytes": 2048,
  "detected_format": "pdf",
  "signature_name": "PDF",
  "extension": ".pdf",
  "format_consistency": "match",
  "signature_offset": 0,
  "signature_hex": "255044462d"
}
```

Supported `detected_format` values are `pdf`, `png`, `jpeg`, `gif`, `zip`,
`pe`, `elf`, and `unknown`. Consistency is `match` only when both a supported
signature and mapped extension agree, `mismatch` when both are known and
disagree, and `unknown` when either side cannot be associated. Known extension
aliases include `.jpg`/`.jpeg` and `.exe`/`.dll`.

The endpoint recognizes PDF, PNG, JPEG, GIF87a/GIF89a, ZIP local/empty/data
descriptor signatures, ELF, and bounded Windows PE candidates. PE requires a
checked `e_lfanew` pointer within the retained 4 KiB prefix and `PE\0\0` at the
target. Recognition does not fully parse or validate a file and does not find
embedded or unsupported structures. The first supported leading signature has
deterministic priority for possible polyglot content.

| Condition | HTTP |
|---|---:|
| Valid nonempty file at or below the configured limit | 200 |
| Empty file, missing field, or invalid filename | 422 |
| File over `ICYLENS_MAX_UPLOAD_BYTES` | 413 |
| Malformed multipart | Appropriate 4xx |
| Unexpected server failure | 500 |

SHA-256 and signature extraction occur inside the existing bounded 64 KiB read
loop. The response is evidence about byte identity and probable leading format,
not a malware verdict. MIME and filename extension remain client-controlled.

## POST `/api/v1/content-inspections/`

Extracts deterministic static facts during the existing single bounded read
pass. Input is `multipart/form-data` with one required `file` part. Success is
HTTP 200 using `ContentInspectionResponse`:

```json
{
  "filename": "sample.bin",
  "size_bytes": 1024,
  "sha256": "a lowercase 64-character hexadecimal digest",
  "detected_format": "unknown",
  "entropy": {
    "shannon_entropy": 6.73,
    "total_bytes": 1024
  },
  "strings": {
    "observed_count": 12,
    "retained_count": 10,
    "truncated": true,
    "raw_strings_exposed": false,
    "minimum_length": 4,
    "maximum_retained_strings": 100,
    "maximum_characters_per_string": 256
  },
  "indicators": [
    {
      "id": "network.url_candidate",
      "category": "network",
      "description": "URL-like printable ASCII pattern observed",
      "source": "printable_ascii",
      "offset": 120,
      "evidence": "https://example.test/[redacted]",
      "severity": "informational"
    }
  ],
  "indicators_truncated": false
}
```

`observed_count` is the exact number of printable ASCII runs meeting the
configured minimum, including runs omitted from retention. `retained_count` is
the bounded number inspected for indicators; these raw values are not returned.
`truncated` becomes true when a qualifying run exceeds the per-string limit or
when the retention-count limit omits a run. `indicators_truncated` states that
additional distinct bounded evidence existed after the response limit.

Entropy uses all accepted bytes and a fixed 256-counter histogram. String
encoding is printable ASCII `0x20..0x7E`; Unicode and UTF-16 are unsupported.
Indicators are informational observations for URL-like patterns, valid IPv4
candidates, PowerShell/command-interpreter/encoded-command references, and
executable or script filename references. URL paths/query values and the last
IPv4 octet are redacted; command evidence contains only matched tokens and file
evidence only the reference category.

| Condition | HTTP |
|---|---:|
| Valid nonempty file at or below the configured limit | 200 |
| Empty file, missing field, or invalid filename | 422 |
| File over `ICYLENS_MAX_UPLOAD_BYTES` | 413 |
| Malformed multipart | Appropriate 4xx |
| Unexpected server failure | 500 |

The endpoint never resolves or visits extracted network locations and never
executes command text. Raw content and reports are not persisted. Pattern
matches and entropy are descriptive features, not malware classification.

## POST `/api/v1/static-analyses/`

Coordinates every currently implemented static extractor through the existing
single-pass content pipeline. Input is `multipart/form-data` with one required
file part named `file`. Success is HTTP 200 using `StaticAnalysisResponse`:

```json
{
  "analysis_id": "f5306fef-f3f3-49bf-b447-b8a9fd09bb17",
  "analysis_type": "static",
  "status": "completed",
  "filename": "sample.pdf",
  "created_at": "2026-10-25T12:00:00Z",
  "completed_at": "2026-10-25T12:00:00.001000Z",
  "fingerprint": {
    "sha256": "a lowercase 64-character hexadecimal digest",
    "size_bytes": 1024,
    "detected_format": "pdf",
    "format_consistency": "match"
  },
  "content": {
    "entropy": {"shannon_entropy": 6.73, "total_bytes": 1024},
    "strings": {
      "observed_count": 12,
      "retained_count": 10,
      "truncated": true,
      "raw_strings_exposed": false,
      "minimum_length": 4,
      "maximum_retained_strings": 100,
      "maximum_characters_per_string": 256
    }
  },
  "indicators": [],
  "indicators_truncated": false,
  "analysis_limitations": [
    {"code": "static_only", "description": "Analysis is limited to static inspection."}
  ]
}
```

The example values are illustrative. `analysis_id` identifies only this
synchronous operation; there is no persistence and therefore no GET-by-ID.
`created_at` and `completed_at` are aware UTC timestamps. `status: completed`
means processing finished, not that the file is clean. No verdict or risk score
is emitted.

Indicators retain the existing ID, category, description, `printable_ascii`
source, byte offset, informational severity, and redacted evidence. String and
indicator truncation remain explicit, so capped evidence is never represented
as exhaustive. Limitation codes cover static-only scope, non-execution, absence
of a malware verdict, non-validating format identification, limits of entropy,
possible benign text matches, and configured processing bounds.

| Condition | HTTP |
|---|---:|
| Valid nonempty file at or below the configured limit | 200 |
| Empty file, missing field, or invalid filename | 422 |
| File over `ICYLENS_MAX_UPLOAD_BYTES` | 413 |
| Malformed multipart | Appropriate 4xx |
| Unexpected processing failure | 500 with a generic detail |

The endpoint uses the same 64 KiB reads, 10 MiB default limit, 4 KiB signature
window, bounded extraction settings, and unconditional upload cleanup as the
existing endpoints. It performs no execution, deserialization, network lookup,
sample/report persistence, malware classification, or scoring.

## FIRST EPSS point lookup

`GET /api/v1/intelligence/epss/{cve_id}` accepts only a case-sensitive CVE
path identifier and performs one current FIRST lookup. HTTP 200 returns the
strict `EPSSLookupResult`: `available` includes exact decimal-string `score`
and `percentile`, `score_date`, freshness, provenance, and limitations;
`not_scored` returns null numeric/date fields and `unavailable` freshness.
Provider failures use 429/502/503/504 rather than pretending to be score
absence. The endpoint accepts no body, URL, provider filters, or batch input.

EPSS probability, percentile rank, score date, retrieval time, API version,
and optional model version remain separate. The current point API provides no
verifiable model-version field, so it is null.

## Unified vulnerability intelligence

`GET /api/v1/intelligence/vulnerabilities/{cve_id}` returns a typed correlation
without asset applicability. `POST .../{cve_id}/assessment` accepts the same
strict `AssetInventory` used by the existing applicability endpoint and adds a
typed applicability resolution. The POST raw body uses the existing configured
byte limit and is never stored.

Both endpoints return complete or partial results as HTTP 200. Source wrappers
preserve distinct NVD, KEV and EPSS statuses, evidence, timestamps, freshness,
safe error codes and limitations. If every source fails, the typed unavailable
response uses 429/502/503/504 according to the recoverable failure classes.
Malformed CVEs/inventories return 422, oversized inventory returns 413, and
unexpected internal failures return sanitized 500 responses.

The contract includes no global risk score. `applicability: null` means no
inventory was supplied; it is not a not-applicable conclusion.

### Lifecycle and report invariants

The operation is synchronous. HTTP 200 always carries `status: "completed"`
and means every required extractor and report-assembly step finished. Input or
processing failures return an HTTP error instead of a queued, processing, or
failed report. The UUID is an operation identifier, not a resource URL; there
is no history or GET-by-ID endpoint.

The response contract enforces:

- valid UUID and literal `static`/`completed` values;
- aware UTC timestamps with `completed_at >= created_at`;
- equal `fingerprint.size_bytes` and `content.entropy.total_bytes`;
- lowercase 64-character hexadecimal SHA-256;
- entropy in the inclusive range 0 through 8;
- `raw_strings_exposed: false`;
- typed indicators, truncation flags, and stable limitation codes;
- rejection of unknown fields throughout the unified report.

Upload, fingerprint, content-inspection, and static-analysis responses remain
specialized contracts: respectively ingestion metadata, deterministic file
characteristics, measured content features, and consolidated evidence. They
are not wrapped in a generic envelope. A future Astro client should generate
or maintain types from OpenAPI, handle non-200 responses separately, and never
render `completed` as a safety verdict.

## Current limitations

- There is no dynamic threat-analysis or malware-verdict endpoint.
- Uploads are validated and discarded; there is no file storage or retrieval.
- MIME is not trusted or inspected. Mapped extensions are compared only with
  detected leading signatures and never treated as proof of safety.
- Signature recognition is intentionally incomplete and is not structural
  format validation or malware detection.
- Only printable ASCII strings are inspected, and indicators can be missed
  after a truncated string preview or retention cap.
- Extracted evidence may still reveal hostnames or command tokens; API access
  must be restricted before use with real user data.
- There is no deployment-level body-size, rate, concurrency, time, memory, or
  temporary-storage quota in application code.
- There are no persisted analysis records or job queue.
- There is no authentication or authorization.
- Swagger and ReDoc remain enabled in every environment.
- The health response does not validate downstream dependencies.
