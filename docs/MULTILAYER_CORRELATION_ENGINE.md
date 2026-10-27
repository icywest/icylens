# Deterministic Multilayer Correlation Engine

Phase 06 checkpoint 06.03 adds an internal, read-only correlation engine over
the immutable evidence boundary from 06.01 and identity resolution from 06.02.
It exposes no API and accepts no caller-supplied identity result. The
orchestrator reruns the trusted identity resolver against the supplied
`EvidenceBatch`, so candidates and records cannot drift.

## Architecture

Responsibilities are separated deliberately:

- `schemas/correlation.py` owns frozen contracts, canonical identifiers,
  categorical statuses, graph shapes and hard limits;
- `correlation/rules.py` owns the immutable sorted built-in registry;
- `correlation/candidates.py` selects only 06.02 groups and diagnostic matches,
  plus explicit 06.01 references;
- `correlation/evaluation.py` evaluates requirements and retained conflicts;
- `correlation/relationships.py` resolves minimized supporting evidence;
- `correlation/graph.py` projects supported relationships into direct edges;
- `correlation/service.py` composes the stages into one bounded result.

No stage reads files, opens a network connection, writes a database, invokes a
subprocess, runs ML/LLM inference or evaluates caller-defined expressions.

## Supported relationships

| Relationship | Required support | It does not establish |
| --- | --- | --- |
| `shared_content_identity` | Exact SHA-256 content group from 06.02 | Same path, host, execution, origin or maliciousness |
| `shared_vulnerability_identity` | Exact canonical CVE group from 06.02 | Installation, applicability, exposure, exploitation or compromise |
| `shared_analysis_context` | Exact source-scoped analysis group from 06.02 | Same sample, device, session, investigation or tenant |
| `explicit_evidence_reference` | Internal reference validated by 06.01 | Identity, causality, time order, execution or maliciousness |

Every relationship contains a deterministic ID, rule/evaluation IDs, exact
evidence IDs, typed identity support where applicable, per-record provenance,
limitations and hard-false inference flags.

`compatible_context` remains auxiliary: it yields a `not_applicable`
evaluation and never a relationship or edge. Common batch membership, matching
labels, nearby timestamps, unversioned model names, probabilities, behavioral
counts, ATT&CK candidates, provider values and free text are not correlation
keys.

## Candidate and graph strategy

The engine never compares every record with every other record. It creates one
candidate per identity group and explicit reference. Diagnostic identity
matches are evaluated only to explain insufficiency, conflict or unsupported
relations. A group of *n* records stays one relationship and projects as at
most *n - 1* direct, rule-supported edges from a stable anchor. This bounded
representation is not transitive inference.

Every node is an existing `EvidenceRecord`. Edges reference published
`supported` relationships only. Relevant identity conflicts change an
evaluation to `conflicting_evidence`, suppress the relationship and remain
visible; the engine never silently applies source precedence.

## Determinism, resources and privacy

Canonical JSON and SHA-256 produce stable IDs. Rules, candidates, evaluations,
conflicts, relationships, nodes and edges have deterministic ordering, so
input permutations produce byte-identical results.

Contracts cap candidates/evaluations at 512, relationships/conflicts at 256,
graph edges at 512, evidence references at 256 per relationship and output at
1 MiB. The inherited batch is capped at 256 records and 1 MiB. A summary
exposes `limits_reached`; work is deterministically truncated.

Outputs remain correlatable and are not anonymous. They contain minimized
digests and categorical provenance, not filenames, raw strings, commands,
free-text payloads or credentials.

06.03 performs no causal inference, temporal reconstruction, attack
progression, malware detection, threat verdict, risk/confidence scoring,
exploitation inference, ATT&CK finding, ML promotion, automatic response,
persistence or external enrichment. Literal false fields enforce these limits.
