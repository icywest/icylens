# Phase 05 checkpoint 05.04 acceptance

## Decision

PASS. The implementation provides deterministic, bounded, explainable
event-sequence and temporal-evidence correlation without causal, maliciousness,
persistence, or ATT&CK inference.

## Acceptance matrix

| Requirement | Evidence |
|---|---|
| Reuse 05.02 validation and contracts | `TemporalCorrelationRequest` contains `EventBatch`; result embeds the unchanged `EventValidationResult`. |
| Preserve 05.03 meaning | Correlation imports no registry/rule evaluator and does not change findings. |
| Distinct timestamps | Event, observation, receipt, deterministic processing, and generation times remain separate and UTC-normalized. |
| Array order is not proof | Canonical `(timestamp, UUID)` ordering; reorder tests preserve the graph; an issue records disorder. |
| Equal/ambiguous time | Equal timestamps create no precedence edge and produce an indeterminate-order issue. |
| Identity rules | Host-scoped process UUID, explicit parent, weak declared file, and weak bounded network tuple rules; PID reuse and host conflicts are issues. |
| Explainable graph | Nodes are submitted events only; every edge carries IDs, type, evidence, confidence, state, limits, and `causal: false`. |
| Unknown/conflict handling | Missing parents/process starts, absent connection identity, conflicting duplicates/hosts/lifecycle, gaps, and future/skew conditions remain explicit. |
| Bounded windows | Default 300 seconds, maximum 86,400; outside-window identity candidates do not form one sequence. |
| Determinism | Canonical output order, deterministic time policy, and UUIDv5 edge/sequence IDs. |
| Resource safety | 256 events/512 KiB input plus edge, per-event, sequence, member, issue, deadline, and 512 KiB output caps; no all-pairs search. |
| Privacy | Graph evidence omits raw command, user, host, path, configuration target/value, and endpoint values. |
| API | Typed POST correlation and read-only GET schema routes in OpenAPI; strict 413/422/503/500 behavior. |
| Isolation | No filesystem, network, dynamic execution, database, continuous ingestion, user-defined expressions, or persistence. |

## Adversarial coverage

Focused offline tests cover process lifecycle, start/termination contradiction,
explicit/missing/cross-host parent, out-of-order input, equal timestamps,
timezone offsets, future/skew/receipt gaps, duplicate and conflicting UUIDs,
PID reuse, process host conflict, file create/modify/rename/delete, same path on
different hosts, missing persistent file identity, attributed/unattributed
network events, tuple reuse outside a window, configuration context, distant
events, invalid policies, deterministic IDs, graph node integrity, acyclic
precedence, relationship/deadline/output limits, no I/O or code execution,
OpenAPI methods, oversized/malformed bodies, and sanitized service failures.

## Scientific boundary

Temporal order is not causal order. Shared process, path, connection tuple,
host, or time window does not establish malicious activity, compromise,
persistence, an attacker, a campaign, or an ATT&CK technique. Missing batch
evidence does not establish non-occurrence.

## Final quality evidence

The unified Quality Gate passed with 844 tests, 94.21% total branch coverage,
Ruff lint and format PASS, strict mypy PASS over 121 source files, and
`pip check` PASS. The 29 focused 05.04 tests and the full regression suite pass.
