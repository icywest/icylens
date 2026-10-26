# ATT&CK mapping explainability

## Structured explanation contract

Every policy evaluation returns a controlled `MappingExplanation`, not an
open-ended generated narrative. It identifies:

- policy ID/version and all evaluated conditions;
- resolved ATT&CK/STIX identity and official catalog facts;
- backend-generated finding and relationship references;
- satisfied, missing, and contradictory conditions;
- declared versus catalog-derived information;
- policy-specific limitations and an invariant scientific boundary.

Evidence references can be independently checked against the submitted event
UUIDs, deterministic backend finding reference, and 05.04 relationship UUID.
They retain declared or synthetic nature. `backend_generated: true` means the
reference was recomputed in this request; it does not transform producer
declarations into independently observed telemetry.

## Negative examples

- A TCP destination port of 443 satisfies `BR-NET-003`. It does not identify
  HTTP/HTTPS content, application intent, Command and Control, or `T1071.001`.
- A command line satisfies `BR-PROC-003`. Without structured interpreter and
  execution semantics, it does not support `T1059`.
- A declared scheduled task creation satisfies `BR-CONF-002`. Without separate
  task-execution evidence, it does not confirm `T1053.005` or persistence.
- `precedes` means earlier event time, not causes. `within_time_window` means
  proximity, not common adversary activity.
- `same_declared_file` is path continuity, not verified physical identity.
- `same_declared_connection` remains weak because endpoint tuples can be reused.

For these examples the explanation includes the positive backend fact and the
missing semantic requirement, and the state is `insufficient_evidence`.

## Candidate boundary

Even if a future trusted policy reaches `candidate`, the result is not proof of
technique execution, malicious activity, endpoint compromise, persistence,
attribution, campaign membership, or malware. It is not a probability or risk
score. Synthetic evidence remains synthetic and cannot validate operational
detection performance.

The assessment contract permanently returns false for confirmed attack,
confirmed malicious activity, malware detection, attribution, vulnerability
mapping, and persistence. CVE, CWE, KEV, and EPSS information is neither read
nor converted into ATT&CK mappings.
