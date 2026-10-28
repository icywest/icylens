# Scenario Provenance and Limitations

## Trust boundary

Scenario evidence originates only from the immutable in-process registry and
is classified as:

- origin: `synthetic_generated`;
- trust classification: `internal_derivation`;
- synthetic: `true`;
- integrity: `structurally_valid`;
- external telemetry authenticated: `false`.

This classification means the backend constructed a valid educational
fixture. It does not authenticate an event outside iCYLENS. The public 06.06
endpoint remains separate: its three input modes always produce
`client_declared`, origin-unverified evidence. It accepts neither scenario
definitions nor `EvidenceBatch`, provenance flags, trusted results or a
backend-generated marker.

No scenario route was added. This intentionally preserves the existing 35
HTTP operations and prevents the educational generator from becoming a second
admission path. The internal service accepts a registered scenario ID and
fixed version only.

## Privacy

Fixtures use reserved educational UUIDs, repeated synthetic digests, invented
CVE-shaped identifiers and generic model/dataset labels. They contain no user
or customer credentials, IP addresses, hostnames, paths, commands, email
addresses, ESET operational data, internal files or real telemetry. Evidence
context explicitly marks paths, commands, users, hosts, network values and raw
payloads as omitted. Reports publish IDs, categories and summaries rather than
raw payloads.

## Negative capability matrix

The library does not demonstrate or claim:

- malware detection or operational ML validity;
- host compromise, file execution or exploitation;
- ATT&CK execution, command and control or persistence;
- attribution, causality or a confirmed investigation narrative;
- installed software, exposure or vulnerability applicability;
- production readiness or authenticated external observation.

SHA-256 equality supports content-digest equality only. CVE equality supports
canonical vulnerability-subject equality only. Analysis UUID equality is
source-module and scope constrained. An explicit reference supports only the
validated link type. Correlation is not causality, a synthetic malicious label
is not an observed fact, and an empty graph is a valid non-positive result.

## Resource and effect boundaries

Generation is pure in-memory construction. Functional execution performs no
network request, provider call, upload, database/object-store write,
filesystem write, subprocess, dynamic code execution, plugin call, LLM/model
execution, malware execution, exploit, persistence, alerting or automatic
response. It reuses the bounded Phase 06 contracts and cannot exceed eight
fixture records per scenario.

Because no HTTP route exists, 06.06 worker concurrency, cancellation and
timeout behavior is unchanged. P05-CONC-003 remains remediated and
P05-CONC-008 remains the documented residual risk; 06.07 neither duplicates
the executor nor expands that risk.
