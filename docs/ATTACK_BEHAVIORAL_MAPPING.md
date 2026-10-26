# Evidence-grounded ATT&CK behavioral mapping

## Scope and architecture

Checkpoint 05.05 evaluates trusted behavioral evidence against a small,
immutable iCYLENS policy registry and resolves technique context exclusively
from the packaged Enterprise ATT&CK 19.2 snapshot.

```text
EventBatch -> 05.02 validation
  +-> backend 05.03 findings
  +-> backend 05.04 temporal graph
  -> evidence resolver -> immutable mapping policies
  -> sufficiency evaluation -> pinned ATT&CK resolution
  -> structured assessment
```

The client submits events and may select registered policy IDs. It cannot
submit findings, evidence graphs, rule definitions, ATT&CK IDs, URLs, scores,
expressions, plugins, or executable policy content. Findings and relationships
are recomputed by the backend. Evaluation performs no network request, disk
write, persistence, ML inference, vulnerability mapping, or text similarity.

## Evidence sufficiency review of the 05.03 registry

The twelve existing rules were reviewed before defining policies:

- Descriptive facts: `BR-FILE-001` and `BR-CONF-001`.
- Missing or inconsistent context: `BR-PROC-001`, `BR-PROC-002`,
  `BR-FILE-002`, `BR-FILE-003`, `BR-NET-001`, and `BR-NET-002`.
- Facts that could contribute to a broader future ATT&CK condition:
  `BR-PROC-003`, `BR-NET-003`, `BR-CONF-002`, and `BR-CONF-003`.
- Independently sufficient for an educational candidate: none.

No file or service mapping was added merely to increase coverage. Missing
parent context is not Process Injection; a file modification is not Impact; a
service change is not Privilege Escalation; and an absent later network state
does not establish Command and Control.

## Built-in policies

| Policy | ATT&CK context | Trusted positive fact | Required evidence absent from schema 1.0.0 |
|---|---|---|---|
| `AMP-PROC-001` | `T1059` Command and Scripting Interpreter | Backend `BR-PROC-003` finding | Structured interpreter identity and execution semantics |
| `AMP-NET-001` | `T1071.001` Web Protocols | Backend `BR-NET-003` finding | Verified application-layer protocol evidence |
| `AMP-CONF-001` | `T1053.005` Scheduled Task | Backend `BR-CONF-002` finding on Windows | Independent evidence that the task executed |

Consequently, built-in policy evaluation intentionally produces zero positive
`candidate` results with the current schema. Matching facts produce
`insufficient_evidence`; a failed condition produces `not_supported`; an absent
family/platform produces `not_applicable`. This is a successful conservative
outcome, not a feature gap to bypass.

The registry supports `candidate` for future trusted policies only when every
minimum requirement is satisfied. It never assigns probability. Policies are
iCYLENS educational controls, not official MITRE detection rules.

## Mapping states

- `candidate`: every minimum policy requirement is present; still only bounded
  educational context.
- `insufficient_evidence`: applicable positive evidence exists, but required
  evidence is missing.
- `not_supported`: trusted evidence fails or contradicts the policy.
- `not_applicable`: required event family/platform is absent.
- `catalog_unavailable`: the pinned knowledge snapshot cannot be resolved.
- `retired_technique`: the referenced object is deprecated or revoked and can
  never become a candidate.

## Identity, time, and catalog semantics

Evidence references preserve event UUIDs and declared/synthetic provenance.
Rule-finding IDs are deterministic UUIDv5 values over canonical event IDs.
Temporal relationship IDs come directly from 05.04. Weak file, connection, or
time-window evidence remains weak and cannot be promoted by mapping.

Catalog results preserve external ATT&CK ID, STIX ID, technique/sub-technique
status, parent, published tactics, platforms, Enterprise domain, version 19.2,
and official MITRE references. Deprecated and revoked objects are retained as
historical knowledge and explicitly reported; they are never treated as active.

## Limits and privacy

Requests retain the 256-event and 512 KiB bounds. Selection is limited to 16
policies; output to 16 evaluations, 16 evidence references per evaluation,
eight event IDs per reference, a one-second evaluation deadline, two-second
operation timeout, four concurrent workers, and 512 KiB serialized output.
Timeout or cancellation retains admission until the actual worker finishes.

Responses use IDs and controlled facts instead of raw command lines, paths,
users, hosts, configuration values, or endpoints. Nothing is stored. Deployment
still requires authentication, authorization, transport security, and external
rate/resource limits before using real telemetry.
