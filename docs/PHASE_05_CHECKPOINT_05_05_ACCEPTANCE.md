# Phase 05 checkpoint 05.05 acceptance

## Decision

PASS. The implementation provides deterministic, catalog-pinned,
evidence-grounded ATT&CK context while correctly producing no built-in positive
candidates from the insufficient 05.02–05.04 evidence.

## Acceptance evidence

- Three immutable, versioned policies reference active techniques present in
  the verified Enterprise ATT&CK 19.2 snapshot.
- All twelve 05.03 rules were classified for evidence sufficiency; none was
  promoted directly to a technique.
- Rule findings and temporal relationships are recomputed from the submitted
  `EventBatch`; client-supplied findings and graphs are forbidden.
- Candidate, insufficient, unsupported, inapplicable, unavailable-catalog, and
  retired-technique states are explicit and carry no numeric probability.
- External ATT&CK ID, STIX identity, type, parent, tactics, platforms, status,
  version, domain, official references, and provenance are preserved.
- Structured explanations separate satisfied, missing, contradictory,
  declared, and official-catalog information.
- Weak temporal evidence remains weak. Equal timestamps, event reordering,
  host/process conflicts, and declared/synthetic provenance remain explicit.
- Requests, policies, evaluations, evidence, event references, strings,
  deadline, timeout, concurrency, and serialized output are bounded.
- Timeout and cancellation do not release capacity until the real worker exits.
- API responses omit raw command lines, paths, users, hosts, configuration
  values, and endpoints and persist nothing.
- No ML, CVE/CWE/KEV/EPSS mapping, external lookup, arbitrary code, text
  matching, semantic similarity, attribution, malware, or compromise inference
  was added.

## Adversarial coverage

Offline tests cover valid/duplicate/unknown policies, real active/deprecated/
revoked catalog objects, catalog unavailability, candidate mechanics for a
test-only trusted policy, insufficient/contradictory/unsupported/inapplicable
evidence, client findings, invented evidence fields, unknown IDs, host/process
conflicts, weak temporal relationships, equal timestamps, reordered events,
TCP/443, command-line and scheduled-task negative semantics, catalog version,
evidence/output bounds, deadline, capacity, timeout, cancellation, no I/O,
no vulnerability/ML inference, OpenAPI, oversized input, and sanitized errors.
The complete suite provides regression coverage for checkpoints 05.01–05.04
and Phase 04.

## Final quality evidence

The unified Quality Gate passed with 867 tests, 94.27% total branch coverage,
Ruff lint and format PASS, strict mypy PASS over 127 source files, and
`pip check` PASS. The 23 focused 05.05 tests and all regressions pass.
