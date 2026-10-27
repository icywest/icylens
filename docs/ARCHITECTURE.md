# iCYLENS Backend Architecture

## Phase 04 Checkpoint 04.03 CISA KEV boundary

The CISA KEV integration separates fixed-host HTTP transport, permissive-current
provider schemas, strict catalog integrity validation, canonical records,
immutable snapshots, indexed lookup, service, and API. One lifespan-owned client
and store serve all requests. Refresh is optional at startup and never occurs on
lookup. Candidate construction occurs off to the side and a single assignment
promotes only a completely validated snapshot; failures retain the previous
snapshot. NVD transport and CVSS/CWE/CPE domains remain independent.

## Phase 04 Checkpoint 04.02 interpretation boundary

`app/vulnerability` is a pure domain layer beneath HTTP services. CVSS and CWE
interpreters consume canonical records; the CPE parser and applicability engine
also consume a strict declared inventory. `VulnerabilityInterpretationService`
coordinates them, while routes only fetch, validate bounded input, map provider
errors, and serialize typed results. The NVD client remains the sole provider
transport boundary and its 04.01.1 streaming/deadline lifecycle is unchanged.

Dependency direction is NVD client → canonical record → interpretation domain →
typed interpretation/assessment. No domain module imports FastAPI or calls an
external service.

## Phase 04 Checkpoint 04.01 NVD boundary

The vulnerability route calls a provider-independent service. The service accepts
validated provider models from a bounded NVD client and builds the versioned
canonical contract. Raw external JSON never reaches route logic. FastAPI owns one
client for its lifespan and closes it on shutdown. Transport, provider schemas,
normalization, and public response contracts remain separate; ML/static-analysis
engines are unchanged. See [`NVD_INTEGRATION.md`](NVD_INTEGRATION.md).

Checkpoint 04.01.1 hardens the transport boundary. Successful responses remain
open and unbuffered until the integration counts decoded chunks; every status,
size, transport, timeout, or cancellation path closes the response. A total
deadline contains semaphore wait, attempts, body streaming, and backoff, while
HTTPX retains per-phase timeouts. Environment-derived proxies and CA bundles are
disabled with `trust_env=False`. Provider `format` and `version` now form part of
the validated boundary rather than inferred provenance.

## System overview

iCYLENS `0.5.0` provides a Python 3.12/3.13 backend foundation, a bounded
static-analysis pipeline, educational ML demo inference, and read-only
vulnerability intelligence backed by NVD, CISA KEV, and FIRST EPSS. FastAPI
exposes versioned HTTP routes, Pydantic defines request and response contracts,
and `pydantic-settings` supplies typed configuration. There are no databases,
durable file stores, dynamic analyzers, or distributed provider caches.

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

## Phase 03 Checkpoint 03.01 ML data boundary

The ML foundation is an offline, framework-independent consumer of the Phase
02 report, not a new HTTP capability:

```text
StaticAnalysisResponse + explicit extraction settings
  -> deterministic feature adapter (no byte reads)
  -> MLFeatureVector 1.0.0 (ordered observations only)
  -> MLDatasetRecord
       identity | features | label | provenance | extraction | split
  -> dataset validation (record errors, warnings, dataset errors)
```

`schemas/ml_features.py` owns strict feature names, domains, version, and
ordering. `schemas/ml_dataset.py` owns the separated record contract.
`ml/features.py` maps existing indicator IDs without importing FastAPI, while
`ml/validation.py` checks eligibility, exact duplicates, label conflicts,
cross-split overlap, provenance, and repeated synthetic templates.

All schema `1.0.0` feature values are mandatory. Missing data is rejected
instead of imputed, and bounded observations retain explicit truncation flags.
SHA-256 is used only for identity/deduplication. The record hierarchy prevents
labels, source metadata, split assignment, analysis UUIDs, timestamps, and
filenames from entering the declared predictive order.

The validator protects exact-hash isolation but cannot identify near-duplicate
or malware-family leakage. A later dataset builder must add deliberate grouped
and temporal split policy, source diversity analysis, immutable manifests, and
sealed test-set custody before training. There is currently no training,
inference, evaluation, endpoint, persistence, CVE intelligence, MITRE mapping,
or behavioral analysis.

## Phase 03 Checkpoint 03.02 dataset pipeline

The offline ML boundary now extends from individual contracts to controlled
dataset releases:

```text
local JSON/JSONL
  -> bounded import
  -> strict record/governance assessment
  -> deterministic exact-hash canonicalization
  -> leakage-safe constrained split planner
  -> records.jsonl + typed manifest + validation report
  -> integrity verification before future training
```

`ml/importing.py` performs bounded UTF-8 JSON/JSONL input. `ml/builder.py`
separates assessment from building and records all exclusions. `ml/splitting.py`
uses versioned, seeded SHA-256 ranking rather than runtime hashing.
`schemas/ml_manifest.py` owns split configuration and manifest contracts.
`ml/artifacts.py` owns staged non-overwriting export and verification. The
argparse CLI in `scripts/dataset_cli.py` exposes validate/build/inspect without
starting or importing the web server.

The content digest covers canonical released records, dataset identity,
builder/feature versions, and split configuration; it excludes its own value
and creation time. Load-time checks independently derive counts, labels,
splits, source IDs, extraction versions, and validation-summary consistency.
Filesystem persistence is limited to authorized metadata artifacts, not
uploaded bytes.

The planner respects prior assignments and rejects infeasible class coverage.
Its only grouping guarantee is exact SHA-256 identity. Family, campaign,
source-cluster, and near-duplicate leakage remain explicit future controls.
There is still no model training, inference, evaluation, FastAPI ML route,
database, cloud storage, or executable-sample persistence.

## Phase 03 Checkpoint 03.03 offline training

The training boundary consumes only dataset artifacts that pass the Phase 03.02
loader and repeats integrity/eligibility checks before matrix construction:

```text
verified manifest + records
  -> training eligibility and resource limits
  -> 14-field feature matrix
  -> per-model ColumnTransformer + estimator Pipeline
  -> fit(training)
  -> predict/metrics(validation)
  -> typed experiment report
  -> staged local model artifacts with byte-level integrity descriptors
```

`ml/preprocessing.py` owns deterministic type conversion, explicit categorical
domains, one-hot encoding, and the stable 23-column transformed contract.
`ml/models.py` owns the three bounded candidate factories. `ml/training.py`
owns eligibility, partition isolation, fitting, validation metrics, and runtime
metadata. `ml/experiments.py` owns non-overwriting staged persistence and
byte-level verification without deserialization. `schemas/ml_experiment.py`
owns configuration, metrics, report, and artifact contracts. The local
`scripts/train_models.py` CLI composes these layers without FastAPI.

Numeric scaling exists only in the Logistic Regression pipeline; both tree
pipelines retain numeric scale. Explicit one-hot categories avoid ordinal
semantics and stabilize output width. Only training is fitted, validation is
transformed, and test features are never constructed in this checkpoint.

Joblib artifacts are pickle-compatible and therefore trusted-local-only. The
application contains no generic model loader, serving endpoint, test evaluation,
hyperparameter search, SHAP, or malware verdict. Future inference must admit a
compatible trusted experiment and reuse its complete fitted Pipeline.

## Phase 03 Checkpoint 03.04 offline evaluation

The evaluation boundary accepts only a verified dataset and fitted Pipelines
held by the current trusted process. `ml/evaluation.py` owns validation-only
metrics, probability checks, threshold summaries, aggregate error analysis,
original-feature permutation importance, comparison, and conservative
selection. `schemas/ml_evaluation.py` owns versioned strict contracts, while
`ml/evaluation_artifacts.py` owns bounded staged JSON persistence.

```text
verified dataset + in-process fitted Pipelines
  -> identity/schema/digest compatibility
  -> validation matrix only
  -> metrics + errors + probabilities + permutation importance
  -> common-basis comparison -> select or abstain
  -> atomic evaluation JSON + digest manifest
```

Test is not transformed, predicted, scored, or used for importance, threshold
analysis, or selection. The CLI retrains and evaluates in one controlled local
process rather than loading pickle-compatible joblib. There are no new FastAPI
routes, model registry, promotion, final test evaluation, local contribution
narratives, SHAP, calibration fit, or security risk score.

## Phase 03 Checkpoint 03.05 trusted local inference

The v1 router now includes a disabled-by-default ML inference route. Application
lifespan owns `TrustedModelRuntime`: with explicit demo configuration, it builds
and verifies deterministic synthetic metadata, invokes existing training once,
validates a fitted Pipeline, and registers Logistic Regression locally. Failure
leaves the runtime rejected/unavailable; shutdown revokes and clears it.

```text
multipart file
  -> existing analyze_static_upload (single bounded read + cleanup)
  -> extract_ml_features (schema 1.0.0)
  -> shared canonical 14-feature row
  -> one trusted in-memory Pipeline (bounded thread admission)
  -> strict synthetic-demo response
```

`services/ml_inference.py` owns availability, non-queuing capacity, existing
static-service composition, thread offload, feature extraction, and response
assembly. `ml/model_runtime.py` owns lifecycle, compatibility and probability
validation. No request can train, name a model path, deserialize an artifact,
access test, select another candidate, or obtain an operational verdict.

## Phase 04 Checkpoint 04.04 FIRST EPSS

Application lifespan owns one hardened `EPSSClient` and one
`EPSSIntelligenceService`. The client validates and bounds the untrusted FIRST
HTTP response; provider Pydantic schemas validate the envelope and decimals;
the service enforces identity, normalizes provenance/freshness, and owns a
bounded process-local TTL/LRU cache; the route exposes only a typed single-CVE
GET. EPSS remains independent of NVD interpretation, KEV snapshots, CPE
applicability, and ML inference. No correlation or combined scoring occurs.

## Phase 04 Checkpoint 04.05 evidence correlation

`VulnerabilityCorrelationService` composes the existing NVD normalization,
CVSS/CWE interpretation, KEV snapshot store, EPSS cached lookup, and CPE
assessment without duplicating provider HTTP. NVD and EPSS execute once in a
two-branch fan-out; KEV remains a synchronous immutable-snapshot read. Typed
recoverable provider failures remain inside their source branch. Unexpected
failures and the correlation-wide deadline abort the request.

The public response carries bounded NVD summary metadata rather than the full
provider-derived document, existing interpretation contracts, optional CPE
assessment, and a structured evidence ledger. No correlation dependency
points toward ML, and request handling cannot refresh KEV.

## Phase 05 Checkpoint 05.01 ATT&CK knowledge foundation

The fixed official Enterprise ATT&CK 19.2 STIX bundle enters only through a
bounded manual importer. Structural and identity validation precede domain
normalization, deterministic compression, and atomic publication. Application
lifespan loads the packaged immutable snapshot once. `ATTACKKnowledgeService`
performs indexed, network-free reads and the `/attack` router exposes bounded
GET contracts. Import failure cannot replace an existing store snapshot, and
no GET triggers download or refresh.

```text
official pinned STIX 2.1 -> bounded importer -> structural/domain validation
  -> immutable compressed snapshot -> knowledge service -> read-only API
```

This component has no dependency on static analysis, synthetic ML, or Phase 04
vulnerability intelligence and makes no behavioral observation.

## Phase 05 Checkpoint 05.02 behavioral event foundation

Strict discriminated event contracts separate common provenance from process,
file, network, and configuration fields. A pure batch validator checks
within-request consistency and returns typed issues without classifying threats.
The deterministic generator derives a bounded immutable response from explicit
scenario configuration and performs no I/O.

```text
typed JSON body -> pre-buffer byte limit -> structural event validation
  -> semantic batch validation -> typed result (no persistence)

scenario + seed + UTC start -> deterministic generator -> same validator
  -> synthetic scenario response (no execution, no ATT&CK mapping)
```

The behavior module has no dependency on the ATT&CK catalog, vulnerability
intelligence, static analysis, or ML. It creates the evidence vocabulary needed
by later phases without implementing rules or temporal correlation.

## Phase 05 Checkpoint 05.03 deterministic behavioral rules

Validated 05.02 event batches enter a stateless engine backed by a frozen,
sorted built-in registry. Family-specific trusted evaluators perform bounded
linear scans, extract capped/redacted evidence, and produce one typed finding
per rule plus separate outcome counts. Request data can select IDs but cannot
define or execute rules.

```text
EventBatch -> 05.02 validation -> immutable registry
  -> process/file/network/configuration evaluators
  -> bounded evidence -> explainable findings
```

The engine does not depend on the ATT&CK catalog, ML, vulnerability sources,
filesystem, network, or persistence. Temporal reasoning is limited to order in
one batch; advanced event-sequence correlation remains 05.04 scope.

## Phase 05 Checkpoint 05.04 event sequence and temporal evidence correlation

The sequence route composes existing event validation with isolated policy,
identity, fixed-rule, evidence-ID, schema, orchestration, and HTTP modules.

```text
bounded EventBatch -> existing validator -> UTC canonicalization
  -> correlation_policy + correlation_identity + correlation_rules
  -> correlation_evidence -> event-only graph + sequences + issues
  -> strict TemporalCorrelationResult
```

`schemas/behavior_correlation.py` owns public contracts and hard limits.
`behavior/correlation_policy.py` owns deterministic processing time and window
semantics; `correlation_identity.py` owns host-scoped declared keys;
`correlation_rules.py` owns bounded adjacency/window primitives;
`correlation_evidence.py` owns deterministic UUIDv5 identities and evidence
construction; `correlation.py` orchestrates without persistence or I/O; and
`api/v1/routes/behavior_sequences.py` maps typed resource failures to sanitized
HTTP responses. The existing pre-buffer middleware applies the 512 KiB limit.

Sorting and hash grouping are O(n log n); rules link adjacent members of each
identity group rather than all pairs. The graph cannot fabricate nodes. Strict
time edges point forward and equal-time ordering remains indeterminate. No
dependency points to ATT&CK, ML, vulnerability intelligence, the filesystem,
the network, a database, or the 05.03 rule registry.

## Phase 05 Checkpoint 05.05 evidence-grounded ATT&CK mapping

The mapping layer composes existing engines but does not let ATT&CK semantics
flow backward into events, findings, or temporal relationships.

```text
EventBatch -> rule engine + temporal engine
  -> evidence references -> immutable policy registry
  -> sufficiency state -> in-memory ATT&CK 19.2 snapshot
  -> bounded structured explanation
```

`schemas/attack_mapping.py` owns public contracts and limits;
`behavior/attack_mapping_policies.py` the three declarative policies;
`attack_mapping_registry.py` identity and catalog validation;
`attack_mapping_evidence.py` canonical backend references;
`services/attack_mapping.py` evaluation, output limits, timeout and admission;
and `routes/behavior_attack.py` sanitized HTTP behavior. The application-owned
capacity counter prevents more than four active workers and remains held across
client cancellation until the underlying thread ends.

The only catalog dependency is the already loaded immutable snapshot. There is
no provider call, free-text technique matching, ML, vulnerability-intelligence
dependency, persistence, or client-defined policy execution.

## Phase 05 Checkpoint 05.06 unified behavioral orchestration

The unified service is a thin composition boundary over the five existing
Phase 05 components:

```text
declared EventBatch -> canonical validator ----------------------+
synthetic request -> existing generator + its validation --------+
                                                                v
  one validation -> one rule evaluation -> one temporal correlation
       -> typed trusted mapping evaluation -> controlled explanation
       -> bounded, privacy-minimized BehavioralAnalysisResult
```

`schemas/behavior_analysis.py` owns strict contracts and global limits;
`services/behavior_analysis.py` owns ordering, status aggregation,
deterministic UUIDv5 identity, privacy minimization, output bounding, admission,
timeout, and cancellation cleanup; and `routes/behavior_analysis.py` owns the
two POST modes, read-only schema route, and sanitized HTTP translation.

The rule and temporal engines accept an optional trusted validation result.
The mapping service exposes a typed internal `evaluate_trusted` method for
backend-generated rule and temporal results. These are Python-only composition
interfaces: HTTP consumers cannot inject a trusted result. The standalone
05.05 mapping endpoint continues to recompute its own evidence.

Blocking semantic validation yields a partial assessment and explicit skipped
stages. Catalog absence yields a partial assessment and unavailable mapping
stage. A loaded catalog with no candidates is complete. The orchestration adds
no reverse dependency into earlier engines, no open-ended explanation engine,
and no persistence, filesystem/network side effect, ML, or vulnerability
intelligence dependency.

## Phase 06 checkpoint 06.01 unified evidence boundary

Phase 02 through 05 response models flow through explicit typed adapters into
frozen `EvidenceRecord` instances and then a deterministically ordered
`EvidenceBatch`. Source models do not depend on the evidence layer, and the
evidence layer does not invoke source engines. This preserves a one-way
dependency and keeps future correlation outside the checkpoint.

The schema separates evidence, subject, analysis, source and batch identities;
origin from trust; representation integrity from factual certainty; and every
timestamp meaning from every other meaning. Canonical SHA-256 IDs are verified
on model construction. Fixed typed observations avoid arbitrary nested data;
tuples and frozen nested contracts provide effective immutability. No evidence
HTTP ingestion route, storage layer or inferred cross-module edge exists.
