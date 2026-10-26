# Deterministic behavioral rule engine

Phase 05 checkpoint 05.03 evaluates the strict event batches introduced in
05.02 using a fixed, trusted registry. A match establishes only that declared
data satisfied a documented rule condition. It does not confirm malware,
compromise, an attack in progress, attribution, or a MITRE ATT&CK technique.

## Architecture and safety

```text
typed EventBatch -> existing structural/semantic validation
  -> immutable built-in registry -> bounded trusted evaluators
  -> redacted evidence -> explainable RuleFinding records
```

Rules are frozen Pydantic objects defined in source code. Registry construction
sorts by ID, rejects duplicate identities and exposes immutable tuples. HTTP can
list rules and select registered IDs, but cannot upload rule definitions,
Python expressions, plugins, imports, scripts, or shell commands. Evaluation
uses explicit Python comparisons only; there is no `eval`, `exec`, dynamic
import, filesystem access, network access, persistence, or background worker.

## Result semantics

- `matched`: at least one supplied event satisfies all coded conditions. This
  means a rule condition matched, not that an attack occurred.
- `not_matched`: applicable event fields were available but the condition was
  not satisfied.
- `insufficient_evidence`: the family applies, but a field or relationship
  required to decide the condition is absent.
- `not_applicable`: no event from the rule family exists, or the trusted rule
  is disabled.

Structural and within-batch issues from 05.02 remain in `batch_validation` and
are not silently rewritten as rule matches.

## Built-in rules

| ID | Family | Declarative condition | Important limitation |
|---|---|---|---|
| `BR-PROC-001` | Process | Start record has no parent identity | Parent collection can be absent normally |
| `BR-PROC-002` | Process | Parent does not predate child or is declared on another host | Clock/source errors can cause inconsistency |
| `BR-PROC-003` | Process | Start record contains command-line context | Content is not returned as evidence |
| `BR-FILE-001` | File | Modification follows same-host/path creation in the batch | No state outside the batch is consulted |
| `BR-FILE-002` | File | Rename lacks process or declared hash metadata | Optional attribution is source-dependent |
| `BR-FILE-003` | File | File operation has no process identity | Network/file-only sources may lack attribution |
| `BR-NET-001` | Network | Attempt has no later established/closed state in the batch | Later state may exist outside the batch |
| `BR-NET-002` | Network | Established record lacks process identity | Network sources may lack process context |
| `BR-NET-003` | Network | Protocol is TCP and destination port is 443 | TCP/443 is routine traffic, not maliciousness |
| `BR-CONF-001` | Configuration | A structured configuration change is reported | Administrative changes can be routine |
| `BR-CONF-002` | Configuration | Scheduled task has no previous value and a current value | Describes declared creation semantics only |
| `BR-CONF-003` | Configuration | Service has previous and current values | Service modification is not inherently malicious |

These rules are deliberately educational and factual. They do not implement
advanced time windows, chain correlation, scoring, heuristics, signatures,
behavioral baselining, or ATT&CK mapping.

## Resource bounds

Evaluation reuses the 05.02 limit of 256 events and 512 KiB per request. It
adds at most 32 rules/findings, eight evidence events per finding, twelve fields
per evidence record, 256 characters per scalar evidence value, a one-second
evaluation deadline, and a 256 KiB serialized output limit. Evaluation order
is stable by rule ID and evidence is deduplicated by event UUID.

