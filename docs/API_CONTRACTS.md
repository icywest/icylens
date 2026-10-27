# iCYLENS API Contracts — Educational Local Release 0.5.0

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
  "version": "0.5.0",
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

## Phase 05 ATT&CK knowledge API

All routes are GET-only under `/api/v1/attack`. IDs are case-sensitive:
`TA####` for tactics and `T####` or `T####.###` for techniques. Malformed IDs
return 422, well-formed absent/hidden retired IDs return 404, and an unavailable
catalog returns 503. Unexpected lookup failures are sanitized as 500.

- `GET /attack/status` returns availability, fixed provenance, statistics,
  historical-object policy, and the `knowledge_not_observation` boundary.
- `GET /attack/tactics` returns a page (`offset`, `limit` up to 200).
- `GET /attack/tactics/{tactic_id}` returns one tactic.
- `GET /attack/tactics/{tactic_id}/techniques` returns associated techniques.
- `GET /attack/techniques/{technique_id}` returns one technique.
- `GET /attack/techniques/{technique_id}/subtechniques` returns official
  children of a parent technique.

List and lookup routes exclude non-active records unless
`include_retired=true`. Responses carry domain, release, official identity,
source STIX identity, lifecycle state, and source references. No route accepts
a remote URL, selects another release, refreshes data, or represents detection.

## Phase 05 behavioral telemetry API

- `POST /api/v1/behavior/events/validate` accepts one strict `EventBatch` of up
  to 256 discriminated events and returns `EventValidationResult`. HTTP 422
  represents structural contract failure; a structurally valid but inconsistent
  batch returns 200 with typed issues and `valid: false` when errors exist.
- `POST /api/v1/behavior/scenarios/generate` accepts an explicit scenario ID,
  scenario kind, seed, platform, UTC start time, and 1–100 bounded events. It
  returns deterministic `SyntheticScenario` data plus validation results.
- `GET /api/v1/behavior/schema` publishes supported event types, resource
  limits, and explicit `persistence: false`, `attack_mapping: false`, and
  `detection_semantics: false` boundaries.

Validation bodies are capped at 512 KiB and generation requests at 64 KiB
before JSON buffering. Oversize returns 413, invalid content-length returns 400,
invalid contracts return 422, and unexpected service failures return sanitized
500 responses. The endpoints do not accept files or output paths, persist
events, contact hosts, perform network requests, execute descriptions, map
ATT&CK techniques, or assert maliciousness.

## Phase 05 behavioral rule API

- `GET /api/v1/behavior/rules` returns the immutable sorted built-in registry,
  including conditions, evidence requirements, limitations, versions, families,
  and enabled state. No write method exists.
- `POST /api/v1/behavior/rules/evaluate` accepts a strict `EventBatch` and an
  optional bounded list of registered rule IDs. Omission evaluates every enabled
  built-in rule. The response contains existing batch validation, deterministic
  findings, separate state counts, evidence, limitations, and false flags for
  persistence, malware classification, and ATT&CK mapping.

Malformed, duplicate, or unknown rule IDs return 422. Oversized request bodies
return 413 before JSON buffering. Evaluation-budget exhaustion returns sanitized
503 and unexpected failures return sanitized 500. The API accepts no rule
definitions, expressions, plugins, scripts, severities, or remote endpoints.

## Phase 05 temporal correlation API

`POST /api/v1/behavior/sequences/correlate` accepts a strict `EventBatch` and
an optional bounded `CorrelationPolicy`. It reuses 05.02 validation and returns
`TemporalCorrelationResult`: deterministic processing metadata, canonical
event nodes, typed relationships, bounded sequences, explicit issues, summary,
limitations, and false flags for causality, ATT&CK mapping, malware
classification, and persistence.

The policy accepts a 1–86,400 second relationship window, bounded skew/future
tolerances, and an optional aware processing time. Without one, processing and
generation time deterministically use the latest declared `received_at`.
Request bodies are limited to 512 KiB before JSON buffering. Invalid contracts
return 422, oversized bodies 413, exhausted correlation budgets 503, and
unexpected errors a sanitized 500.

`GET /api/v1/behavior/sequences/schema` exposes the relationship, confidence,
state, and hard-limit vocabulary and is read-only. Neither route accepts
expressions, rules, files, storage targets, external endpoints, or continuous
streams. Responses do not echo raw command lines, paths, host IDs, users,
configuration values, or network endpoints.

## Phase 05 evidence-grounded ATT&CK mapping API

`GET /api/v1/behavior/attack/policies` returns the immutable iCYLENS mapping
registry, catalog availability/version, evidence requirements, platforms,
limitations, and retired-object policy. It accepts no write method.

`POST /api/v1/behavior/attack/map` accepts a strict `EventBatch`, optional
registered policy IDs, and an optional bounded correlation policy. It does not
accept findings, graphs, rule definitions, ATT&CK IDs, URLs, scores, or code.
The backend recomputes 05.03 findings and 05.04 relationships before evaluating
the selected policies against the in-memory Enterprise ATT&CK 19.2 snapshot.

HTTP 200 returns `AttackMappingAssessment` with catalog provenance, rule and
temporal summaries, typed evaluations, evidence references, structured
explanations, state counts, limitations, and false security-verdict flags.
`candidate` is educational context, never confirmed execution. Current built-in
policies require evidence absent from schema 1.0.0 and therefore do not create
positive candidates.

Malformed or duplicate selections return 422; bodies over 512 KiB return 413;
capacity exhaustion returns 429; deadline, operation-timeout, or nested-engine
budget exhaustion returns 503; and unexpected failures return sanitized 500.
The response omits raw telemetry values and is capped at 512 KiB. No catalog
network call, persistence, ML, vulnerability mapping, malware classification,
attribution, or attack confirmation occurs.

## Phase 05 unified behavioral analysis API

`POST /api/v1/behavior/analyze` accepts a strict `BehavioralAnalysisRequest`
with a canonical batch and bounded registered selections. The service always
revalidates declared events. A blocking semantic inconsistency returns a typed
HTTP 200 `partial` result with downstream stages `skipped`; structural failures
remain 422.

`POST /api/v1/behavior/scenarios/analyze` accepts one strict seeded 05.02
scenario specification and the same analysis options. It uses only the existing
generator and returns the same `BehavioralAnalysisResult` contract. `GET
/api/v1/behavior/analysis/schema` publishes sources, global/stage states, and
hard limits.

The result includes deterministic analysis identity and generation time,
provenance and event counts, validation, minimized rule findings, temporal
relationships/sequences, mapping evaluations and catalog version, five stage
records, issues, summaries, controlled explanation, limitations, and false
verdict flags. Events and raw evidence values are not echoed.

Requests are limited before buffering to 512 KiB for declared batches and 64
KiB for scenario specifications. The service allows 256 declared or 100
synthetic events, one scenario per call, a 3-second pipeline deadline, 4-second
operation timeout, 1 MiB encoded response, and four active workers. HTTP 413,
422, 429, 503, and sanitized 500 retain distinct meanings. It accepts no code,
URLs, dynamic rules/policies, trusted client findings/graphs, free-form ATT&CK
IDs, export paths, persistence targets, or executable content.

## Internal unified evidence contracts

Checkpoint 06.01 intentionally adds no public evidence endpoint. The internal
`EvidenceRecord`/`EvidenceBatch` schema is version `1.0.0`, strict, frozen and
bounded to 256 records, 32 KiB per record, 1 MiB per batch, 16 references per
record and fixed schema depth eight. Static, ML, vulnerability and behavioral
observations use a discriminator and prohibit arbitrary fields.

Only typed backend source models can enter the adapters. Unknown module or
schema versions and mismatched model types fail with controlled normalization
errors. A descriptor is available as a Python function for internal consumers;
there is no `/correlate`, `/investigations`, `/threat-score`, `/detections` or
client-accreditation route.

## Phase 06 unified multilayer analysis API

`POST /api/v1/multilayer/analyze` accepts
`MultilayerAnalysisRequest/1.0.0`. The strict JSON body contains one to 16
discriminated declared sources and one to 32 registered assertion selections.
Enabled source modes are `declared_static`, `declared_vulnerability` and
`declared_ml`. The only response mode is `explainable`.

Every admitted observation becomes origin-unverified, client-declared
evidence. The route rejects internal evidence batches, engine responses,
identity/correlation results, sufficiency assessments, traces, trust flags,
dynamic rules and executable instructions. Unknown syntactically valid
assertions retain the 06.04 `unsupported_assertion` state.

HTTP 200 returns `MultilayerAnalysisResponse/1.0.0`: canonical analysis/batch
IDs, evidence provenance summaries, identity and correlation reference IDs,
sufficiency assessment summaries, complete decision traces, static limitations
and false capability flags. Cross-result references and the 1 MiB response
limit are validated.

Bodies over 256 KiB return 413 before validation. Redacted 422 covers schema
and admission failures; 429 covers queue-free worker exhaustion; 503 covers
resource limits; 504 covers the four-second wait deadline; unexpected or
inconsistent results return redacted 500. Timeout and cancellation do not free
worker occupancy before real completion.

`GET /api/v1/multilayer/schema` publishes only safe modes, registered assertion
IDs, supported domains, limits, response contract and scientific limitations.
The two routes increase the surface from 33 to 35 operations without changing
legacy route contracts.
