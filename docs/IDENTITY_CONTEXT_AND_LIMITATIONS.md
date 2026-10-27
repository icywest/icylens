# Identity Context and Limitations

Identity resolution answers which explicit identifiers can be compared. It
does not answer whether evidence is malicious, causally related, operationally
co-located or part of one investigation.

## Context preservation

Every `IdentityContext` retains the evidence ID, source module and phase,
source analysis ID, subject category, semantic timestamps, environment-scope
category, origin, trust classification, synthetic status and verification
status. `common_batch_assumed` is permanently false.

Analysis-start, analysis-completion, generation, event, observation, receipt,
intelligence-publication, modification and retrieval clocks keep their own
meanings. UTC normalization from 06.01 is preserved. Time proximity is not an
identity rule and no missing event time is synthesized.

## Valid assumptions

- Two exact SHA-256 claims under `sha256` can identify equal content digests.
- Two canonical CVE claims under `cve` can identify the same vulnerability.
- Equal analysis UUIDs can identify one analysis only when source module and
  declared scope are also equal.
- A validated explicit derivation reference can establish compatible context.

## Invalid assumptions

- Equal SHA-256 does not prove the same physical file, host, user, path or
  execution.
- Equal PID without host scope and process-instance identity proves nothing.
- A CVE does not prove installed software, exposure or exploitation.
- A model name without an independent model version is not versioned model
  identity.
- T1059 text without STIX ID, domain and pinned catalog version is incomplete
  ATT&CK identity; even complete technique identity would not confirm execution.
- A prediction and a behavioral finding are not one threat identity.
- A CVE and an ATT&CK technique are different entity types.
- Batch co-membership, similar labels or nearby timestamps do not establish a
  session, device, tenant, investigation or causal relationship.

## Conflicts

The engine reports unsupported namespaces, invalid canonical identifiers,
duplicate evidence references and one source-analysis identifier associated
with different explicit subjects. It never silently selects one source.

Host-scope and process-instance conflicts cannot currently be evaluated because
those attributes are absent from 06.01 evidence. Their absence is recorded as
unresolved rather than agreement. Mismatched `explicit_same_subject`
references are already rejected by the 06.01 `EvidenceBatch` contract.

## Trust and scientific boundary

Resolution copies provenance without promotion. Client-declared remains
client-declared, synthetic remains synthetic, external intelligence remains
externally reported, and representation integrity is not converted into
factual certainty.

Outputs have hard false flags for persistence, threat correlation, attack
findings, risk scores, exploitation inference and promotion of ML output to an
observation. Static evidence is never runtime behavior; CVE identity is never
exploitation evidence; ATT&CK identity is never attack confirmation.

## Privacy and operational limitations

Results contain evidence IDs, identity categories, namespace categories,
field categories, safe explanations and minimized deterministic digests. They
do not expose filenames, paths, hosts, users, commands, IPs, registry values,
secrets, raw source payloads, CVE text, provider URLs or original identifiers.

Deterministic digests can still enable linkage. They are pseudonymous
references for bounded processing, not anonymity or cryptographic attestation.

The resolver performs no filesystem or network I/O, persistence, command or
dynamic-code execution, model inference, external lookup, fuzzy matching or
source-engine rerun.
