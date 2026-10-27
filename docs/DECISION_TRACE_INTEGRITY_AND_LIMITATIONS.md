# Decision Trace Integrity and Limitations

This document defines what Phase 06 checkpoint 06.05 validates and what a
valid decision trace cannot establish.

## Deterministic identifiers

Trace (`dtr_`), node (`trn_`), edge (`tre_`), statement (`tst_`) and limitation
(`tli_`) IDs use SHA-256 over sorted compact canonical JSON. Nodes bind type,
object and state; edges bind type and endpoints; statements bind template
version and source reference. A trace binds its source assessment, assertion,
state, policy versions and ordered node, edge and statement IDs.

Construction sorts every collection. Equal batches and selections therefore
produce equal semantic graphs and serialized JSON regardless of input order.
There are no clocks, random values, embeddings, network lookups or LLM calls.
A digest detects content inconsistency; it is not a signature, independent
origin authentication or an anonymity guarantee.

## Structural and semantic validation

Pydantic reconstruction verifies:

- canonical IDs, strict versions, deterministic order and uniqueness;
- exact correspondence between typed references and graph node objects;
- node type/state agreement with assessment, requirement, identity and
  correlation states;
- existing edge endpoints, no self-loops, no cycles and maximum depth;
- policy/assertion agreement and no policy for unsupported assertions;
- exact template coverage for the assessment, every requirement,
  contradiction, uncertainty and limitation;
- summary counts, requirement outcomes, graph depth and result size.

The service uses only results created in the same internal orchestration.
Schema validity never promotes a consumer-supplied trace to trusted. Requests
have no field for precomputed analytical results or a trust override.

## Bounds and complexity

| Resource | Limit |
| --- | ---: |
| Traces per request | 32 |
| Nodes per trace | 128 |
| Edges per trace | 256 |
| Dependency depth | 8 |
| Explanation statements | 64 |
| Evidence references | 16 |
| Identity references | 16 |
| Correlation references | 16 |
| Requirements | 8 |
| Contradictions | 16 |
| Uncertainty references | 32 |
| Limitations | 16 |
| Serialized result | 1 MiB |

The layer inherits all earlier limits. Lineage uses sets and dictionaries over
bounded existing results. Graph construction is linear in retained references;
DAG validation is `O(nodes + edges)`. It does not expand transitive paths,
enumerate evidence combinations or rebuild historical phase output.

## Privacy boundary

Output includes deterministic IDs, typed categories and minimized provenance.
It excludes original payloads, paths, commands, users, hosts, IP addresses,
registry values, secrets, raw telemetry and source descriptions. Static
messages interpolate no evidence value or free text. Tests scan the complete
serialized result with privacy canaries. Deterministic IDs remain correlatable
and must not be treated as anonymous.

## Contradiction and uncertainty limits

Only contradictions already relevant to the 06.04 assessment are included.
Unrelated batch conflicts are not propagated. References retain the affected
requirement, evidence IDs, source conflict ID and absence of source precedence.

Uncertainty is copied from the 06.04 categorical taxonomy with evidence
references and `affects_sufficiency`. No probability, confidence, severity or
risk is derived. A narrow assertion can be sufficient while operational
context remains uncertain; that is not an inconsistency.

## Scientific limitations

A trace shows which software inputs and registered rules supported a backend
decision. It does not show that evidence is factually true, an external event
happened or one event caused another:

- digest equality is content identity, not file execution or malware;
- CVE identity is not installation, vulnerability or exploitation;
- source-scoped analysis identity is not a shared host or causal sequence;
- an explicit reference proves a validated declaration, not causality;
- declared or synthetic provenance is not authenticated telemetry;
- ML output remains a model observation, not operational validation;
- absence of retained contradiction is not universal truth.

No endpoint, persistence, database, filesystem write, provider call,
subprocess, alert, report store, automatic response or 06.06 API is part of
this checkpoint.
