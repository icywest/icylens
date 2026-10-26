# iCYLENS

## Phase 05 temporal evidence correlation

Checkpoint 05.04 adds bounded, deterministic event-time correlation at
`/api/v1/behavior/sequences`. It returns explainable event-only graphs and
identity sequences with explicit confidence, ambiguity, conflicts, and hard
resource limits. Temporal precedence and proximity never imply causality,
maliciousness, persistence, or ATT&CK execution. See
[`docs/BEHAVIORAL_TEMPORAL_CORRELATION.md`](docs/BEHAVIORAL_TEMPORAL_CORRELATION.md)
and [`docs/BEHAVIORAL_EVIDENCE_GRAPH.md`](docs/BEHAVIORAL_EVIDENCE_GRAPH.md).

## Phase 05 deterministic behavioral rules

Checkpoint 05.03 adds a fixed, read-only registry of twelve educational rules
and bounded evidence-based evaluation at `/api/v1/behavior/rules`. Findings
explain declared conditions; they are not malware verdicts, confirmed attacks,
or automatic ATT&CK mappings. See
[`docs/BEHAVIORAL_RULE_ENGINE.md`](docs/BEHAVIORAL_RULE_ENGINE.md) and
[`docs/BEHAVIORAL_FINDINGS_CONTRACT.md`](docs/BEHAVIORAL_FINDINGS_CONTRACT.md).

## Phase 05 behavioral telemetry foundation

Checkpoint 05.02 adds strict process, file, network, and configuration event
contracts; semantic batch validation; and ten deterministic offline educational
scenarios under `/api/v1/behavior`. Events are not persisted or executed and
are not automatically mapped to ATT&CK. See
[`docs/BEHAVIORAL_EVENT_SCHEMA.md`](docs/BEHAVIORAL_EVENT_SCHEMA.md) and
[`docs/SYNTHETIC_TELEMETRY_GENERATOR.md`](docs/SYNTHETIC_TELEMETRY_GENERATOR.md).

## Phase 05 ATT&CK knowledge foundation

Checkpoint 05.01 adds a pinned, offline Enterprise ATT&CK 19.2 STIX 2.1
catalog and read-only `/api/v1/attack` endpoints. It distinguishes tactics,
techniques, sub-techniques, STIX relationships, lifecycle state, and source
provenance. Catalog membership is knowledge, never evidence that a behavior
was observed. See
[`docs/MITRE_ATTACK_KNOWLEDGE_BASE.md`](docs/MITRE_ATTACK_KNOWLEDGE_BASE.md) and
[`docs/ATTACK_STIX_DATA_CONTRACTS.md`](docs/ATTACK_STIX_DATA_CONTRACTS.md).

## Phase 04 vulnerability intelligence

Checkpoint 04.03 adds an independent, read-only CISA KEV snapshot integration.
It securely refreshes the canonical catalog only through an internal optional
startup policy, validates and indexes complete snapshots atomically, and exposes
`GET /api/v1/intelligence/kev/status` plus
`GET /api/v1/intelligence/kev/{cve_id}`. KEV presence is known-exploitation
evidence, not proof of local impact or compromise. See
[`docs/CISA_KEV_INTEGRATION.md`](docs/CISA_KEV_INTEGRATION.md) and
[`docs/KEV_CATALOG_LIFECYCLE.md`](docs/KEV_CATALOG_LIFECYCLE.md).

Checkpoint 04.01 adds a read-only typed integration with the official NVD CVE API
2.0 at `GET /api/v1/vulnerabilities/CVE-2021-44228`. It validates identity,
bounds HTTP work and response size, and returns canonical CVE, CVSS, CWE, CPE,
reference, provenance, and limitation contracts. It does not scan assets, confirm
exploitation, detect malware, or calculate risk. See
[`docs/NVD_INTEGRATION.md`](docs/NVD_INTEGRATION.md) and
[`docs/CVSS_CWE_CPE_INTERPRETATION.md`](docs/CVSS_CWE_CPE_INTERPRETATION.md).

Checkpoint 04.02 adds conservative CVSS/CWE interpretation and CPE applicability
assessment against a bounded declared inventory. It uses three-valued logic and
never labels an asset confirmed vulnerable. Use
`GET /api/v1/vulnerabilities/{cve_id}/interpretation` or POST a strict inventory
to `/api/v1/vulnerabilities/{cve_id}/applicability`. See
[`docs/CPE_APPLICABILITY_ENGINE.md`](docs/CPE_APPLICABILITY_ENGINE.md) and
[`docs/VULNERABILITY_DATA_CONTRACTS.md`](docs/VULNERABILITY_DATA_CONTRACTS.md).

iCYLENS is an experimental cybersecurity analysis platform. Phase 02 now
provides a typed FastAPI backend with bounded, non-persistent file ingestion,
deterministic static feature extraction, and a unified static-analysis report
in addition to the Phase 01 foundation.

Phase 01 baseline: `0.1.0`, technically accepted on 2026-10-25 after an
independent audit. See the [architecture](docs/ARCHITECTURE.md),
[API contracts](docs/API_CONTRACTS.md),
[audit report](docs/PHASE_01_AUDIT_REPORT.md), and
[acceptance record](docs/PHASE_01_ACCEPTANCE.md).

## Backend prerequisites

- Python 3.12 or 3.13
- PowerShell commands below are run from `C:\icylens\apps\api`

## Local setup

Clone or otherwise obtain the repository, then enter the backend directory:

```powershell
git clone <repository-url> icylens
Set-Location .\icylens\apps\api
```

When the repository already exists at the documented location:

```powershell
Set-Location C:\icylens\apps\api
```

Create the environment and install the declared development dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
Copy-Item .env.example .env
```

The `dev` extra installs the runtime dependencies plus pytest, pytest-cov,
HTTPX, Ruff, and mypy.
The project currently uses compatible version ranges rather than a lockfile;
strict deployment locking can be added when the deployment workflow is chosen.

`.env` contains local configuration and is ignored by Git. `.env.example` is a
safe, versioned template. The application also works without a `.env` file.

## Configuration

All external variables use the `ICYLENS_` prefix:

| Variable | Default | Purpose |
|---|---|---|
| `ICYLENS_APP_NAME` | `iCYLENS API` | Application and health-service name |
| `ICYLENS_APP_VERSION` | `0.4.1` | API and health-service version |
| `ICYLENS_APP_ENV` | `development` | `development`, `testing`, or `production` |
| `ICYLENS_DEBUG` | `false` | FastAPI debug mode; forbidden in production |
| `ICYLENS_API_V1_PREFIX` | `/api/v1` | Prefix for v1 routes |
| `ICYLENS_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL` |
| `ICYLENS_MAX_UPLOAD_BYTES` | `10485760` | Positive upload byte limit; maximum configurable value is 1 GiB |
| `ICYLENS_INSPECTION_MIN_STRING_LENGTH` | `4` | Minimum printable ASCII run length |
| `ICYLENS_INSPECTION_MAX_STRINGS` | `100` | Maximum strings retained internally for inspection |
| `ICYLENS_INSPECTION_MAX_STRING_LENGTH` | `256` | Maximum characters retained from one string |
| `ICYLENS_INSPECTION_MAX_INDICATORS` | `100` | Maximum returned static indicators |

Operating-system environment variables take precedence over values in `.env`,
which take precedence over code defaults. Unknown `.env` values are ignored so
unrelated local variables do not prevent startup. Settings are cached once per
process; tests clear that cache when changing environment variables.

## Run the API

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Swagger is available at <http://127.0.0.1:8000/docs> and the health endpoint at
<http://127.0.0.1:8000/api/v1/health/>. Interactive documentation remains
available in all environments for this foundation phase. Production rejects
debug mode, and the default command binds only to the local interface.

## Secure file ingestion

`POST /api/v1/uploads/` accepts one required `file` part as
`multipart/form-data`. A valid, nonempty file of at most 10 MiB returns HTTP
201 with a generated operation UUID, its validated original filename, measured
byte count, client-declared content type, `status: "validated"`, and
`persisted: false`.

The filename is untrusted metadata. It must be 1-255 printable characters,
contain no `/` or `\\`, and not equal `.` or `..`. The service reads bounded
64 KiB chunks, never executes or deserializes the content, and closes and
discards it after validation. Empty/invalid uploads return 422 and files over
the configured limit return 413. The declared MIME type is reported but is
not format detection or a security verdict.

Starlette parses multipart data before the route runs and may spool files over
1 MiB to a framework-managed temporary file. The application creates no file
or durable record, and explicitly closes the `UploadFile`; Starlette owns
cleanup of parser resources. This application limit is not a whole-request
cap. A reverse proxy or ASGI server request-body limit, concurrency controls,
timeouts, and OS resource limits remain necessary before public exposure.

## File fingerprinting

`POST /api/v1/fingerprints/` accepts the same required multipart `file` field
and security policy as ingestion. During the existing single bounded read pass,
it calculates SHA-256 over the original bytes, measures their size, and retains
at most the first 4 KiB for signature identification. The bytes are closed and
discarded after the response.

Supported leading signatures are PDF, PNG, JPEG, GIF87a/GIF89a, three ZIP
signatures, ELF, and a Windows PE candidate. PE requires `MZ`, a bounded
little-endian `e_lfanew` value, and `PE\0\0` at that exact location; `MZ` alone
is insufficient. Other or truncated content is reported as `unknown`.

The result includes the lowercase SHA-256 digest, measured bytes, detected
format, signature evidence, lowercase filename extension, and `match`,
`mismatch`, or `unknown` extension consistency. MIME is not used for detection.
An extension match or recognized signature identifies bytes; it does not prove
structural validity, safety, or absence of malware. Nested/embedded formats,
full container validation, uncommon signatures, entropy, strings, YARA, and
malware classification are not implemented.

Example request:

```powershell
curl.exe -F "file=@sample.pdf;type=application/pdf" http://127.0.0.1:8000/api/v1/fingerprints/
```

SHA-256 is an incremental cryptographic digest: matching digests provide strong
evidence that two byte sequences are identical, but a digest alone says
nothing about whether those bytes are safe.

## Static content inspection

`POST /api/v1/content-inspections/` accepts the same bounded multipart `file`
input and performs fingerprinting, entropy accumulation, printable-string
extraction, and indicator matching during one 64 KiB-chunk read pass. The file
is closed and discarded afterward.

Byte-level Shannon entropy is calculated as `H(X) = -sum(p(x) * log2(p(x)))`
from a fixed 256-counter histogram. Results range from 0 bits/byte for one
repeated value to 8 bits/byte for a balanced byte distribution. High entropy
can describe compression, encryption, or packing; it is not a malware verdict.

String extraction supports printable ASCII bytes `0x20` through `0x7E` only.
Runs cross chunk boundaries. At most 100 strings and 256 characters per string
are retained by default; longer strings keep their first bounded preview, and
the response explicitly reports truncation. `observed_count` counts every
qualifying run, while `retained_count` counts the bounded internal subset.
Raw strings are never returned, logged, or persisted.

Indicators cover URL-like text, valid IPv4 candidates, PowerShell and command
interpreter references, encoded-command tokens, and executable/script filename
references. Output is deduplicated, capped, informational, and uses evidence
redaction: URL paths/query data and the last IPv4 octet are hidden. Matching a
pattern does not imply malicious behavior, resolve an address, visit a URL, or
execute a command.

Memory added by inspection is bounded by a 256-counter histogram, the existing
4 KiB signature prefix, configured retained-string previews, bounded indicator
evidence, and one read chunk. Unicode/UTF-16 strings, embedded decoding, YARA,
full parsing, verdicts, and risk scoring are not supported. Before inspecting
real user files, restrict API access and add deployment-level request,
concurrency, time, memory, and temporary-storage controls.

## Unified static analysis

`POST /api/v1/static-analyses/` is the consolidated synchronous entry point.
It accepts one required multipart `file`, delegates to the existing content
inspection pipeline, and returns a generated operation UUID, aware UTC
timestamps, fingerprint and format evidence, entropy, bounded string
statistics, redacted indicators with source and byte offsets, truncation state,
and stable limitation codes. The operation identifier does not imply storage;
neither the sample nor the report is persisted or retrievable by ID.

All extractors observe the same 64 KiB chunk stream. The orchestration layer
adapts their existing results and does not reread or copy the complete file.
`completed` means processing completed, not that the content is safe. The
report deliberately has no verdict or risk score and explicitly states that
format detection is not structural validation, entropy is not maliciousness,
and textual matches may be benign. Existing upload, fingerprint, and content
inspection endpoints remain unchanged.

The endpoint has a synchronous lifecycle: validation and processing either
finish with HTTP 200 and `status: "completed"`, or terminate with an HTTP error.
It does not expose queued, processing, or failed resources. Report validation
requires UTC timestamps in chronological order and matching fingerprint and
entropy byte counts; unknown report fields are rejected. Unexpected failures
return a generic 500 while recording only the exception type, and upload
cleanup remains guaranteed by the shared ingestion layer.

```powershell
curl.exe -F "file=@sample.pdf;type=application/pdf" http://127.0.0.1:8000/api/v1/static-analyses/
```

A future asynchronous API can create a separate persisted job resource with
queued/processing states and GET-by-ID semantics. That resource does not exist
today. A planned Astro client can consume the current OpenAPI schema directly,
treat 200 as a completed computation, and render limitations and errors without
interpreting completion as a security verdict.

## ML data foundation

Phase 03 starts with data governance rather than model training. The backend
now defines feature schema `1.0.0`, a framework-independent adapter from the
existing static report, strict dataset records, supervised-training eligibility
rules, and dataset-level leakage checks. SHA-256, labels, provenance, split,
filenames, UUIDs, and timestamps are not predictive inputs.

The committed ML fixture is safe synthetic metadata, remains `unassigned`, and
exists only to test validation and serialization. No classifier, prediction
endpoint, score, external dataset, or executable sample is included. See
[`docs/ML_FEATURE_CONTRACT.md`](docs/ML_FEATURE_CONTRACT.md) and
[`docs/ML_DATASET_GOVERNANCE.md`](docs/ML_DATASET_GOVERNANCE.md).

The Phase 03.02 local dataset pipeline additionally accepts bounded UTF-8 JSON
or JSONL, reports deterministic deduplication and eligibility decisions, plans
seeded label-stratified splits, emits a typed manifest with a canonical digest,
and writes versioned artifacts without overwrite. Generated artifacts under
`datasets/generated/` are intentionally ignored by Git. See
[`docs/ML_DATASET_PIPELINE.md`](docs/ML_DATASET_PIPELINE.md) for the format,
security limits, CLI commands, and integrity policy.

Phase 03.03 adds an offline training CLI for three bounded baselines: Logistic
Regression, Random Forest, and HistGradientBoosting. Each model owns its fitted
`ColumnTransformer` inside a scikit-learn `Pipeline`; preprocessing fits on
training only, exploratory metrics use validation only, and test remains sealed.
Experiments are staged under the ignored `experiments/generated/` tree and are
never overwritten. See
[`docs/ML_TRAINING_PIPELINE.md`](docs/ML_TRAINING_PIPELINE.md). Synthetic smoke
metrics are explicitly not evidence of real malware detection performance.

Phase 03.04 adds typed validation-only evaluation: per-class/error/probability
metrics, bounded threshold analysis, aggregate privacy-conscious error groups,
original-feature permutation importance, deterministic model comparison, and a
selection policy that can abstain. Evaluation reuses trusted in-process
Pipelines and never deserializes arbitrary joblib artifacts or opens test.
Generated reports under `evaluations/generated/` are ignored by Git. See
[`docs/ML_MODEL_EVALUATION.md`](docs/ML_MODEL_EVALUATION.md). Synthetic results
remain technical smoke tests and cannot authorize model selection or deployment.

Phase 03.05 adds `POST /api/v1/ml-inferences/` for an explicitly enabled local
synthetic demonstration. Lifespan initialization builds a governed metadata-only
dataset, trains once, validates one trusted in-memory Pipeline, and reuses it;
HTTP requests never train or load serialized models. Defaults keep inference
and demo mode disabled. See
[`docs/ML_INFERENCE_API.md`](docs/ML_INFERENCE_API.md). Launch a demonstration
with explicit `--host 127.0.0.1`; public exposure is not authorized.

## Testing and quality gates

The suite uses pytest markers to make its intent explicit:

- `unit`: isolated settings, schema, and utility behavior.
- `integration`: assembled FastAPI behavior through `TestClient`.
- `contract`: request validation and response/OpenAPI contracts.
- `security`: repository and environment-configuration safety checks.

All tests override every supported setting before importing the application,
use controlled settings, and require no internet connection, database, or
listening network port. A developer's local `.env` cannot change test outcomes,
and tests never modify it. Run the complete suite with:

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

Branch coverage is measured over `app` and must remain at or above 85%. HTML
and XML reports are written to `htmlcov/` and `coverage.xml`:

```powershell
.\.venv\Scripts\python.exe -m pytest --cov=app --cov-branch --cov-report=term-missing --cov-report=html --cov-report=xml
```

Ruff enforces imports and selected defect-oriented lint rules and verifies
canonical formatting. Mypy checks `app` and `scripts` in strict mode:

```powershell
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe -m pip check
```

The unified gate runs each mandatory check with the active Python interpreter
and returns nonzero if any check fails:

```powershell
.\.venv\Scripts\python.exe scripts\quality_gate.py
```

A failure identifies its gate in the output. Fix the underlying lint,
formatting, typing, test, coverage, or dependency issue and rerun the command.
Coverage indicates executed code, not correctness; assertions and realistic
failure-path tests remain essential even when coverage is high.

Dependency vulnerability scanning is not part of the mandatory offline gate.
The Phase 01 audit ran `pip-audit` in a disposable clean virtual environment
and found no known vulnerabilities in the declared dependency closure. Add an
audit step to CI when network and advisory-database access are available.

## FIRST EPSS point intelligence

Phase 04.04 adds a secure, read-only FIRST EPSS point lookup at
`GET /api/v1/intelligence/epss/{cve_id}`. Scores retain decimal precision and
their FIRST publication date; absence, freshness, and provenance are explicit.
EPSS is neither CVSS severity nor proof of exploitation or compromise. See
[`docs/FIRST_EPSS_INTEGRATION.md`](docs/FIRST_EPSS_INTEGRATION.md) and
[`docs/EPSS_SCORE_SEMANTICS.md`](docs/EPSS_SCORE_SEMANTICS.md).

## Unified vulnerability intelligence

Phase 04.05 correlates NVD, CVSS/CWE interpretation, the active CISA KEV
snapshot, and FIRST EPSS by exact CVE identity. The GET endpoint returns source
evidence without asset assumptions; the POST assessment optionally evaluates
the existing CPE tree against a bounded declared inventory. Source failures are
isolated and no combined score or compromise conclusion is produced. See
[`docs/UNIFIED_VULNERABILITY_INTELLIGENCE.md`](docs/UNIFIED_VULNERABILITY_INTELLIGENCE.md)
and [`docs/EVIDENCE_CORRELATION_POLICY.md`](docs/EVIDENCE_CORRELATION_POLICY.md).
