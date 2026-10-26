# ATT&CK STIX data contracts

The importer consumes a bounded STIX 2.1 bundle and publishes immutable domain
contracts. STIX IDs and ATT&CK external IDs are always distinct.

## Normalization

An `x-mitre-tactic` becomes `ATTACKTactic`: official `TA####`, STIX ID, name,
optional description and short name, explicit domain, references, object/spec
versions, lifecycle flags/status, and optional created/modified timestamps.

An Enterprise `attack-pattern` becomes `ATTACKTechnique`: official `T####` or
`T####.###`, STIX ID, name, optional description, explicit parent identity,
sub-technique marker, resolved tactics, platforms, references, versions,
lifecycle flags/status, and timestamps. Optional source fields remain `null`;
they are not rewritten as negative assertions.

A STIX `relationship` becomes `ATTACKRelationship`: relationship STIX ID,
source/target STIX IDs, relationship type, domain/release provenance, and
lifecycle flags. Both endpoints are required to resolve within the complete
bundle before publication. Tactic membership is separately normalized from
`kill_chain_phases`.

External references are bounded records with source name plus optional external
ID, URL, and description. Only a unique `mitre-attack` reference supplies the
canonical ATT&CK identity; unrelated references need not have an external ID.

## Snapshot contract

`ATTACKCatalogSnapshot` contains provenance, mapping-proxy indexes for tactics
and techniques, an immutable relationship tuple, and validated statistics.
Construction is all-or-nothing. `ATTACKCatalogStore.load()` builds a candidate
before replacing the current reference, so failure preserves the last valid
snapshot. Consumers cannot mutate its mappings or frozen Pydantic records.

Limits include 64 MiB raw input, 50,000 objects, 40,000 relationships, JSON
depth 20, 131,072-character STIX strings, bounded references/phases/platforms,
16 MiB expanded local snapshot, and 200 API results per page. Duplicate STIX
IDs, duplicate external identities, contradictory parents, malformed IDs,
domain mismatches, unresolved references, corrupt JSON/gzip, and count
mismatches fail closed.

Synthetic test data is clearly named `attack_bundle_synthetic.json`; it is not
a redistribution or representative sample of the full MITRE catalog.

