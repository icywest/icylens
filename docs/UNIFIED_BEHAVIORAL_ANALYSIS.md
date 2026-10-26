# Unified Behavioral Analysis

Checkpoint 05.06 exposes one deterministic, evidence-grounded assessment while
keeping the Phase 05 engines independently usable:

```text
canonical batch OR seeded synthetic specification
  -> 05.02 semantic validation
  -> 05.03 immutable behavioral rules
  -> 05.04 bounded temporal correlation
  -> 05.05 conservative ATT&CK policy evaluation
  -> controlled explanation template
  -> BehavioralAnalysisResult 1.0.0
```

The orchestrator does not reimplement rules, correlation, mapping, or scenario
generation. It computes validation, findings, and correlation once per request.
The mapping service has a typed internal `evaluate_trusted` path for those
backend-produced results; its public 05.05 endpoint retains the original safe
behavior and recomputes evidence from events supplied over HTTP.

## Input modes and trust boundary

`POST /api/v1/behavior/analyze` accepts `BehavioralAnalysisRequest`: a canonical
`EventBatch` and optional registered rule IDs, registered mapping-policy IDs,
and a bounded correlation policy. The server always performs 05.02 validation;
there is no client `validated` flag or trusted finding/graph input.

`POST /api/v1/behavior/scenarios/analyze` accepts `SyntheticAnalysisRequest`:
one existing 05.02 scenario specification and the same options. The existing
seeded generator creates at most 100 events and its canonical validation result
is reused. One request can generate exactly one scenario. Neither endpoint
accepts URLs, paths, code, executable payloads, expressions, dynamic rules,
plugins, free-form ATT&CK IDs, or output destinations.

## Result contract

Both modes return `BehavioralAnalysisResult` schema `1.0.0`, including:

- deterministic UUIDv5 `analysis_id`, deterministic evidence-derived
  `generated_at`, input source, and declared/synthetic provenance;
- event-family counts and the complete typed validation result;
- privacy-minimized rule finding summaries, temporal relationships and
  sequences, ATT&CK mapping evaluations, summaries, and catalog version;
- exactly five stage records, unified issues, aggregate counts, a controlled
  explanation, limitations, and explicit false security-verdict flags.

The response intentionally does not echo events or raw rule evidence. It omits
command lines, user names, full paths, host names, configuration values, and
network endpoints. Event UUID references preserve traceability without copying
sensitive telemetry. Nothing is persisted or written to logs.

The deterministic analysis identity covers canonical ordered events, source,
scenario identity, and options. Identical input produces the same ID, ordering,
states, interpretation, and generated time. There is no wall-clock timestamp in
the factual result.

## Status semantics

Stage status is one of `completed`, `skipped`, `unavailable`, or `failed`.
A completed stage with zero results is distinct from a stage that did not run.
Global status is `complete`, `partial`, or `unavailable`; `unavailable` remains
part of the stable contract for a request whose required pipeline cannot run.

A structurally valid batch with blocking semantic validation issues receives
HTTP 200 and global `partial`. Validation and explainability complete; rules,
temporal correlation, and ATT&CK mapping are explicitly skipped. No invalid
event is silently discarded and no downstream engine receives that batch.

Catalog absence is different: validation, rules, and correlation complete,
mapping evaluations retain `catalog_unavailable`, the mapping stage is
`unavailable`, and the global result is `partial`. A loaded catalog with zero
`candidate` results is a normal completed analysis.

Mapping states retain the 05.05 meanings: `candidate`,
`insufficient_evidence`, `not_supported`, `not_applicable`,
`catalog_unavailable`, and `retired_technique`. A rule match is not promoted to
an ATT&CK candidate. The present built-in policies normally yield zero positive
candidates because the schema lacks their independent semantic evidence.

## Explainability and scientific boundary

`BehavioralAnalysisExplanation` is assembled from a fixed template. It states
the input nature, validation outcome, rule counts, non-causal relationship
counts, mapping-policy counts, missing evidence, and interpretation boundary.
It uses no LLM or open-ended narrative generation. There is no global risk or
attack score, malware verdict, causal reconstruction, attribution, or SOC
response claim.

## Resource and execution safety

- declared batches: 256 events and 512 KiB request body;
- generated scenarios: 100 events and 64 KiB specification body;
- one scenario per request; registered selections and nested engine limits;
- global synchronous pipeline deadline: 3 seconds;
- asynchronous operation timeout: 4 seconds;
- unified encoded output: 1 MiB;
- process-local non-queuing concurrency: four workers;
- evidence, relationships, sequences, issues, and mapping evaluations retain
  their typed caps.

Input, output, evidence, and worker bounds constrain request memory; no unbounded
fan-out or all-pairs relationship expansion is introduced. CPU work runs in a
thread so the event loop remains responsive. Python cannot forcibly stop that
synchronous worker: on timeout or external cancellation, the admission slot is
therefore retained until the worker actually exits. No long operation holds the
capacity lock, and deferred cleanup observes the worker to avoid orphaned task
exceptions or premature capacity release.

HTTP 413 reports body limits, 422 invalid contracts or unknown registered
selections, 429 exhausted capacity, 503 computation budgets, and 500 an
unexpected sanitized failure.

## Residual risks

The API trusts declared telemetry content after structural and consistency
validation; it does not collect or independently verify host observations.
In-process thread timeouts bound client waiting, not CPU preemption. Admission
is process-local rather than distributed. Authentication, authorization,
durable jobs, SIEM ingestion, real-time streams, and operational monitoring are
outside this checkpoint. Consumers must keep the explicit evidence limitations
visible and must not reinterpret educational candidates as observed attacks.
