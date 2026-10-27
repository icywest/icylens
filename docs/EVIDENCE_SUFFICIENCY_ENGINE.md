# Evidence Sufficiency Engine

Phase 06 checkpoint 06.04 adds an internal deterministic assessment layer over
validated 06.01 evidence, recomputed 06.02 identity resolution and recomputed
06.03 correlation. It answers only whether explicit requirements support a
registered statement about the data. It does not answer whether an attack,
malware execution, exploitation or compromise occurred.

## Processing boundary

```text
EvidenceBatch -> 06.02 identity resolution -> 06.03 correlation
  -> static assertion policy -> requirement evaluation
  -> relevant contradictions + categorical uncertainty
  -> bounded sufficiency assessment
```

The request contains only a validated `EvidenceBatch` and bounded selections
of assertion IDs plus evidence IDs. It cannot contain trusted flags, identity
results, correlation graphs, policies or prior assessments. The service
recomputes both prerequisite layers and verifies their batch IDs before use.

Implementation responsibilities are separated:

- `schemas/sufficiency.py`: strict frozen contracts, states, IDs and limits;
- `sufficiency/rules.py`: immutable assertion registry;
- `sufficiency/resolver.py`: indexed evidence, group and relationship lookup;
- `sufficiency/contradictions.py`: assertion-scoped conflict relevance;
- `sufficiency/uncertainty.py`: categorical uncertainty classification;
- `sufficiency/evaluation.py`: independent requirement evaluation;
- `sufficiency/service.py`: trusted orchestration and summary.

## Registered assertions

| Assertion | Supported statement | Required 06.03 relation |
| --- | --- | --- |
| `AS-CONTENT-001` | Selected records share comparable SHA-256 content identity | `shared_content_identity` |
| `AS-VULN-001` | Selected records refer to the same canonical CVE | `shared_vulnerability_identity` |
| `AS-ANALYSIS-001` | Selected records share exact source-scoped analysis context | `shared_analysis_context` |
| `AS-REF-001` | A validated explicit evidence reference links the records | `explicit_evidence_reference` |

Policies also declare applicable domains, evidence types, identity status and
namespace, provenance requirements, contradiction conditions, limitations and
a safe explanation template. They contain no executable expression or score.

An unknown but syntactically valid assertion ID receives
`unsupported_assertion`. The engine does not substitute a nearby policy or
create a relationship to answer it.

## Requirement semantics

Each policy evaluates its requirements independently:

- selected evidence records exist in the exact batch;
- structured provenance is available and preserved per record;
- the required exact 06.02 identity group exists, where applicable;
- the required supported 06.03 relationship covers the selection;
- no relevant retained conflict contradicts the required property.

Requirement states are `satisfied`, `missing`, `conflicting` and
`not_applicable`. Each result carries bounded evidence/relationship IDs and a
safe explanation. A satisfied relationship requirement cannot make a separate
missing identity or provenance requirement satisfied.

## Assessment semantics

- `sufficient`: every required condition is satisfied with no relevant gap or
  contradiction. This is relative only to the registered statement.
- `insufficient_evidence`: a required condition is absent. This does not prove
  the assertion false.
- `conflicting_evidence`: a relevant retained conflict prevents a positive
  assessment; no source is selected as authoritative.
- `not_applicable`: selected domains do not match the policy.
- `unsupported_assertion`: no policy exists for the requested statement.

For example, SHA-256 identity may be sufficient for content equality but can
never satisfy file execution. CVE equality may establish a common
vulnerability subject but not installation or exploitation. Shared analysis
context is not shared device identity. An explicit reference proves only that
the validated declaration exists, not causality.

## Determinism and resources

Canonical JSON/SHA-256 IDs cover requirement evaluations, gaps,
contradictions, uncertainty reasons and assessments. Input and assertion
permutations produce the same ordered result. Runtime clocks are not included.

Limits include 32 assertion selections, eight requirements per policy, 16
evidence references per assessment, 256 evaluation operations, 256 gaps, 128
contradictions, 256 uncertainty reasons and a 1 MiB serialized result. Lookup
uses dictionaries plus existing identity groups and relationships; it performs
no subset search, Cartesian comparison or exponential combination.

## Privacy and non-capabilities

Outputs use evidence/assertion/requirement/relationship IDs, safe categories
and minimized categorical provenance. They exclude paths, commands, users,
hosts, IP addresses, registry values, secrets, telemetry and source free text.
Deterministic digests remain correlatable and are not anonymous.

The engine has no endpoint, persistence, network/filesystem/database access,
subprocess, plugin, ML/LLM execution or continuous ingestion. It emits no
probability, confidence score, risk, verdict, causal sequence, response action
or trust promotion.
