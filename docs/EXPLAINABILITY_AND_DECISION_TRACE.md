# Explainability and Decision Trace

Phase 06 checkpoint 06.05 adds an internal, deterministic explanation layer
over decisions already produced by checkpoints 06.01 through 06.04. It records
which backend evidence, rules and intermediate results were used. It does not
prove that an external event occurred or reinterpret an analytical decision.

## Processing boundary

```text
validated EvidenceBatch
  -> one 06.02 identity resolution
  -> one 06.03 correlation using that identity result
  -> one 06.04 sufficiency evaluation using both results
  -> lineage extraction -> decision DAG -> integrity validation
  -> static, structured explanation
```

`DecisionTraceRequest` accepts only an `EvidenceBatch` and one to 32 bounded
`AssertionSelection` values. It cannot accept prerequisite results, a trace, a
`trusted` flag, executable policy, narrative or free text. `explain_decisions`
is an internal Python service; 06.05 adds no HTTP route.

New composition helpers bind prerequisite results to the exact batch before
reuse. The orchestrator performs each earlier engine once without creating a
second sufficiency implementation, while existing public functions retain
their behavior.

## Contracts and lineage

All contracts in `app/schemas/explainability.py` inherit the strict frozen base
model and reject unknown properties. A result contains versioned traces and
minimized typed references for:

- selected evidence ID, source module/phase, origin type, trust class,
  synthetic flag and existing verification state;
- registered assertion policy and registry versions;
- relevant 06.02 identity group or match, rule and categorical state;
- a 06.03 relationship actually supporting a requirement, or the exact
  evaluation explaining why the selected pair lacked one;
- every 06.04 requirement evaluation, relevant contradiction, uncertainty
  reason and registered limitation.

Declared provenance remains declared. Synthetic evidence remains synthetic.
An origin or content digest is never described as independent authentication.

## Decision graph semantics

This is a decision-dependency DAG, not the correlation graph from 06.03. Node
types are evidence, identity resolution, correlation relation, assertion,
policy, requirement, contradiction, uncertainty and limitation. Direct edge
types are `uses_evidence`, `evaluated_by`, `depends_on_identity`,
`depends_on_correlation`, `satisfies_requirement`, `missing_requirement`,
`conflicts_with`, `qualified_by` and `limited_by`.

The assertion is the root. Every requirement remains visible. Identity and
correlation nodes attach to the requirement that uses them; contradictions
attach only to the affected requirement. Uncertainty and limitations qualify
the assessment. No transitive edge, temporal sequence, causal connection or
relationship based merely on co-occurrence is added.

## Static explanations and states

Statements select from an exact, versioned template table. Templates contain
no sample values and are never produced by an LLM. There is one decision
statement, one for every evaluated requirement and one for every retained
contradiction, uncertainty and limitation. Validation rejects omitted,
duplicated or state-inconsistent statements.

- `sufficient`: all requirements for this registered statement passed.
- `insufficient_evidence`: missing requirements remain visible; this is not
  falsity.
- `conflicting_evidence`: both sides remain without source precedence.
- `not_applicable`: the policy does not cover the selected domains.
- `unsupported_assertion`: no policy exists and no heuristic is substituted.

## Minimized examples

```text
AS-CONTENT-001: sufficient
  evaluated_by -> AS-CONTENT-001@1.0.0
  uses_evidence -> evd_<digest>, evd_<digest>
  satisfies_requirement -> all five requirement evaluations
  required_identity_satisfied -> idg_<digest> / IR-FILE-001 / same_identity
  required_correlation_supported -> crr_<digest> / supported
  limited_by -> registered content-identity limitation
```

```text
AS-CONTENT-001: insufficient_evidence
  selected_evidence_exists: satisfied
  required_identity_satisfied: missing
  required_correlation_supported: missing
  uncertainty: categorical reason from 06.04
  explanation: required evidence is missing; absence is not falsity
```

```text
AS-ANALYSIS-001: conflicting_evidence
  required_identity_satisfied: conflicting
  contradiction: source conflict ID + affected evidence IDs
  source_precedence_applied: false
  explanation: conflict retained; no source selected as authoritative
```

## Non-capabilities

Literal false flags prohibit causal explanation, threat confirmation, changed
decisions, persistence, scoring, threat verdicts and response actions. A trace
does not establish malware, compromise, CVE exploitation, ATT&CK execution,
file execution, command and control, persistence, attribution, attack sequence
or operational ML validity.

See
[`DECISION_TRACE_INTEGRITY_AND_LIMITATIONS.md`](DECISION_TRACE_INTEGRITY_AND_LIMITATIONS.md)
for integrity, resource, privacy and scientific constraints.
