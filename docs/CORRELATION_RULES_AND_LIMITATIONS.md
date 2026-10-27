# Correlation Rules and Limitations

The 06.03 registry is static, immutable, sorted and versioned as
`correlation-rules/1.0.0`. Rules declare candidate sources, typed requirements,
allowed namespaces, explanations and limitations. Request-defined rules,
dynamic expressions and scores are forbidden.

## Registry

| Rule | Candidate | Outcome |
| --- | --- | --- |
| `CR-CONTENT-001` | 06.02 `file_content` / `sha256` group | `shared_content_identity` |
| `CR-VULN-001` | 06.02 `vulnerability` / `cve` group | `shared_vulnerability_identity` |
| `CR-ANALYSIS-001` | 06.02 `analysis` / `analysis_uuid` group | `shared_analysis_context` |
| `CR-REF-001` | Validated explicit 06.01 reference | `explicit_evidence_reference` |
| `CR-CONTEXT-001` | Compatible-context match | `not_applicable`; no relationship |
| `CR-UNSUPPORTED-001` | Other diagnostic match or group | No relationship |

Positive rules require typed support, retained per-record provenance and no
relevant identity contradiction. Trust classes are reported, never ranked or
promoted.

## Categorical outcomes

- `supported`: all required typed conditions exist and no relevant conflict
  exists; a relationship may be emitted.
- `insufficient_evidence`: an identifier, namespace, version or context
  attribute is unavailable.
- `conflicting_evidence`: identity evidence contradicts the candidate; no
  relationship is emitted and the conflict remains visible.
- `not_applicable`: compatible context cannot satisfy a relationship rule.
- `unsupported_relation`: no approved 06.03 semantic covers the evidence.

These states are not probabilities, confidence, rankings, severity or risk.

## Negative matrix

None of these creates a positive relationship by itself:

- common batch membership, timestamp equality/proximity or matching labels;
- filenames, rule names or free text;
- ML labels/probabilities, unversioned model IDs or dataset membership;
- behavioral or ATT&CK candidate counts;
- CVSS, CWE, EPSS, KEV or provider values without exact supported identity;
- PID without host/process-instance scope;
- equal UUID text across source modules;
- compatible context or an `A-B-C` compatibility chain;
- contradicted or duplicate references.

SHA-256 equality identifies byte-stream content only. CVE equality identifies a
vulnerability subject only. Source-scoped analysis equality identifies an
analysis context only. Explicit references retain their declaration but their
graph projection is non-causal and non-temporal.

The evidence surface does not preserve host-scoped process instances or
individual ATT&CK technique/STIX/catalog tuples. Current Phase 03 evidence has
no independent model version. Those identities remain unresolved and cannot be
correlated positively.

P05-CONC-008 remains an inherited educational-local lifecycle condition. This
pure in-memory layer adds no worker, endpoint or concurrency lifecycle and does
not alter that condition.
