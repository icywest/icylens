# Synthetic Investigation Scenarios

Checkpoint 06.07 provides an offline, immutable library of backend-generated
educational cases. It is an internal Python interface, not an evidence-ingest
or detection API:

```python
from app.scenarios import execute_synthetic_scenario

result = execute_synthetic_scenario("scenario_shared_file_content")
```

The registry contains 11 versioned cases. Ten implement the required A–J
families; a separate cross-module UUID case makes namespace separation
observable without weakening the positive source-scoped context case.

| Scenario ID | Expected assessment | Positive relationship |
| --- | --- | --- |
| `scenario_shared_file_content` | `sufficient` | shared content identity |
| `scenario_conflicting_file_identity` | `conflicting_evidence` | none |
| `scenario_shared_vulnerability_identity` | `sufficient` | shared vulnerability identity |
| `scenario_unrelated_vulnerabilities` | `insufficient_evidence` | none |
| `scenario_shared_analysis_context` | `sufficient` | shared analysis context |
| `scenario_cross_namespace_analysis` | `insufficient_evidence` | none |
| `scenario_explicit_evidence_reference` | `sufficient` | explicit evidence reference |
| `scenario_insufficient_cross_module` | `not_applicable` | none |
| `scenario_unsupported_threat_assertion` | `unsupported_assertion` | none |
| `scenario_synthetic_provenance` | `sufficient` | shared content identity |
| `scenario_empty_non_positive_correlation` | `insufficient_evidence` | none |

## Separation of responsibilities

The definition declares bounded fixture inputs, registered assertion
selections, learning objectives, structured expectations and scientific
boundaries. It cannot contain scripts, expressions, arbitrary seeds, evidence
batches, graphs or precomputed analytical results.

The generator assigns fixed values and canonical evidence IDs, marks every
record `synthetic_generated` / `internal_derivation`, builds validated explicit
references and performs no I/O. The unchanged 06.02–06.05 services calculate
identity, correlation, sufficiency and traces. Only after those services
finish does the validator compare typed statuses, relationship categories,
conflict counts, gap categories and uncertainty categories. A mismatch is a
failed validation; it never edits the observed result.

## Determinism and limits

- Registry version and scenario version are `1.0.0`.
- At most 16 registry entries, eight evidence records and eight expectations
  are permitted by the scenario contracts.
- IDs are canonical SHA-256 identifiers. Definitions contain fixed UUIDs,
  digests and CVEs; there is no clock, randomness, filesystem or network input.
- Records and output references use deterministic ordering. The compact report
  is capped at 512 KiB and 32 decision-trace references.
- One scenario is executed per call. There is no bulk runner, persistence,
  queue, provider lookup, subprocess, model/LLM invocation or response action.

## Results captured from real executions

The following values were produced by the implementation on 2026-10-27; they
are not fabricated response examples.

`scenario_shared_file_content` produced batch
`evb_aaad85d597e8d04ac6b5377906045513bb5d5a3c04ba5a6b0dd06f03ba763f51`,
assessment `sufficient`, relationship `shared_content_identity`, uncertainty
categories `missing_temporal_context` and `synthetic_origin`, trace
`dtr_6dee688804e1f1ba05e9cd09a88cb34cef0f3ce6be20f4cd1ddd136f4e059056`,
and validation `passed`.

`scenario_conflicting_file_identity` produced batch
`evb_26d4675b63c8e778b0156995f786ab65d4094523399fc8477f06b9c777db312e`,
one relevant conflict, no relationship, assessment `conflicting_evidence` and
validation `passed`. `scenario_unsupported_threat_assertion` produced
`unsupported_assertion`, no relationship and validation `passed`.

These results demonstrate narrow registered assertions only. They are not
malware detections, attack observations or production telemetry.
