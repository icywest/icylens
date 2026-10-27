# Unified Multilayer Analysis API

Phase 06 checkpoint 06.06 exposes the existing 06.01–06.05 chain through two
bounded endpoints:

- `POST /api/v1/multilayer/analyze`
- `GET /api/v1/multilayer/schema`

The API has educational local scope. It does not add an analytical engine,
change a decision, persist an analysis, query an external provider, execute a
model or produce a threat score.

## Request contract

`MultilayerAnalysisRequest/1.0.0` is strict and frozen. It contains one to 16
declared sources, one to 32 assertion selections, a fixed `explainable`
response mode and a fixed educational context. Assertions select source IDs;
the backend maps them to evidence IDs only after admission and normalization.

Three discriminated input modes are enabled:

| Mode | Accepted declaration | Backend treatment |
| --- | --- | --- |
| `declared_static` | SHA-256, byte count and analysis-context UUID | Client-declared static observation; the digest is not recomputed from bytes |
| `declared_vulnerability` | Canonical CVE and analysis-context UUID | Client-declared CVE identity; no NVD, KEV or EPSS query |
| `declared_ml` | Model/dataset identifiers, version, digest, label and probability pair | Client-declared educational prediction; no model is executed |

All modes become `client_declared`, `origin_verified=false`,
`origin_unverified` evidence. The endpoint accepts no `EvidenceBatch`, engine
response, identity result, correlation graph, sufficiency result, decision
trace, trust flag, rule expression or execution instruction.

Example:

```json
{
  "schema_version": "1.0.0",
  "sources": [
    {
      "input_type": "declared_static",
      "source_id": "src_first",
      "analysis_context_id": "00000000-0000-0000-0000-000000000001",
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "size_bytes": 128
    },
    {
      "input_type": "declared_static",
      "source_id": "src_second",
      "analysis_context_id": "00000000-0000-0000-0000-000000000002",
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "size_bytes": 128
    }
  ],
  "assertions": [
    {
      "assertion_id": "AS-CONTENT-001",
      "source_ids": ["src_first", "src_second"]
    }
  ]
}
```

The result may be `sufficient` for comparable declared SHA-256 equality. That
does not establish that the bytes existed, were executed or were malicious.

## Single-computation orchestration

```text
strict HTTP request -> admission -> normalized EvidenceBatch
  -> one identity resolution
  -> one correlation using that identity result
  -> one sufficiency evaluation using both results
  -> one trace construction using all three results
  -> cross-result consistency validation -> response
```

The explainability service has an exact-batch internal composition function so
the API does not rerun identity, correlation or sufficiency. The router only
selects the worker, invokes the service and translates typed failures.

## Response contract

`MultilayerAnalysisResponse/1.0.0` includes:

- deterministic analysis and batch IDs;
- source-to-evidence mappings and categorical provenance;
- identity summary plus published match/group IDs;
- correlation summary plus supported relationships and reference IDs;
- sufficiency summary plus assessment IDs, states and evidence IDs;
- complete 06.05 decision traces;
- trust, scientific and operational limitations;
- literal false flags for persistence, external I/O, dynamic execution,
  scoring, verdicts, malware, exploitation, ATT&CK execution, causality and
  response action.

The response validator checks evidence closure, prerequisite references,
assessment/trace coverage, summary counts, canonical analysis identity and the
1 MiB output bound. Source and assertion permutations produce identical JSON.

## HTTP errors and limits

| Status | Meaning |
| --- | --- |
| 413 | Body exceeds 256 KiB before JSON validation |
| 422 | Schema, source admission or source selection is invalid |
| 429 | The bounded worker manager has no available slot |
| 500 | Unexpected or internally inconsistent result |
| 503 | Output or another resource budget was exceeded |
| 504 | Four-second operation wait expired |

Validation and runtime errors use constant messages. They do not echo input
values, exception messages, paths or stack traces.

The endpoint shares the lifecycle-owned four-worker manager already used by
Phase 05. It has no queue. Timeout or client cancellation stops only the
waiter; capacity remains occupied until the synchronous worker actually
finishes. Shutdown closes admission and drains every owned worker.

`GET /api/v1/multilayer/schema` publishes only modes, registered assertion
IDs, domains, limits, response contract and scientific limitations. It exposes
no secrets or private runtime configuration.
