# Behavioral evidence graph

## Graph contract

The 05.04 graph is a finite directed multigraph. Its node set is exactly the
unique event UUIDs submitted in the current request; correlation cannot create
a process, file, host, connection, or activity node that was not observed as an
event. Each edge names two existing event UUIDs and one typed relationship.

The canonical node order is event time followed by event UUID. `precedes` edges
point forward only when the source timestamp is strictly earlier. Equal-time
events are explicitly indeterminate. `follows` is represented in the schema
vocabulary but is not emitted as a reverse edge, preventing a factual temporal
pair from appearing as a cycle.

## Edge evidence

An edge includes:

- a deterministic UUIDv5 relationship identity;
- typed source and target event UUIDs;
- relationship type, categorical confidence, and semantic state;
- `within`, `outside`, `unknown`, or `insufficient` window assessment;
- bounded factual evidence and bounded limitations;
- an invariant `causal: false` marker.

`precedes` means only that one declared event time is earlier. A
`within_time_window` edge means only bounded proximity on the same declared
host. Strong process and parent edges require explicit instance identities.
File and connection edges remain weak because schema 1.0.0 lacks persistent
file and connection identifiers.

Negative possibilities are not materialized as edges. Doing so would require
all-pairs work and could misleadingly present absence as knowledge. Instead,
issues explain insufficient identity, missing in-batch context, conflicting
hosts/times, reuse, out-of-window candidates, truncation, and timestamp
ambiguity. `not_related` remains a contract state for consumers, not an excuse
to manufacture exhaustive negative edges.

## Sequence construction

Sequences are ordered projections of consecutive, within-window identity
edges. Process sequences use explicit host-scoped process instance identity;
file sequences use declared host/path continuity; network sequences use the
declared tuple plus process identity. A gap beyond the configured window splits
a sequence. Each sequence has a deterministic UUIDv5 identity, start/end event
times, confidence, state, member UUIDs, and limitations.

The graph and sequence list are evidence views, not a reconstructed attack
story. They do not alter 05.03 findings, assert that an unsubmitted event never
happened, fill gaps, identify an actor, label persistence, or infer ATT&CK
techniques.

## Safety invariants

- No edge may refer to a non-event node or to the same event twice.
- Strict temporal edges cannot cycle because their event times increase.
- UUID tie-breaking never creates temporal evidence.
- Host conflicts cannot establish process or parent identity.
- PID, path, IP, or endpoint equality alone is not promoted to strong identity.
- Per-event, total-edge, sequence, issue, deadline, body, and output caps fail
  closed or report deterministic truncation.
- Evidence does not echo raw paths, commands, users, hosts, or endpoints.
- The graph performs no external I/O, persistence, rule execution, detection,
  malware classification, causal inference, or ATT&CK mapping.
