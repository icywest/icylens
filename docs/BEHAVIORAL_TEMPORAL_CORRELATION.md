# Behavioral temporal correlation

## Scope

Checkpoint 05.04 correlates only the bounded behavioral events supplied in one
request. It normalizes timestamps, resolves explicit identities, applies fixed
relationship rules, and returns a directed evidence graph and bounded
sequences. It does not read a database, retain history, contact a host, execute
content, evaluate 05.03 rules, map ATT&CK, classify malware, or infer causality.

```text
EventBatch -> 05.02 validation -> canonical UTC ordering
  -> identity resolution -> fixed correlation rules
  -> bounded relationships/sequences/issues -> typed response
```

The API is `POST /api/v1/behavior/sequences/correlate`. A read-only descriptor
is available at `GET /api/v1/behavior/sequences/schema`.

## Time model

Five times remain distinct:

- `timestamp` is the producer-declared event time and determines canonical
  temporal order.
- `observed_at` is when the source says it observed the event.
- `received_at` is when that declaration was received.
- `processing_time` is the correlation reference time.
- `generated_at` is response generation time and equals `processing_time` by
  deterministic policy; it is not a wall-clock sample.

Every timestamp requires a timezone and is normalized to UTC by the 05.02
contracts. Canonical order is `(event_time, event_id)`. UUID ordering is only a
stable presentation tie-breaker: events with equal timestamps receive no
`precedes` edge and produce `EQUAL_EVENT_TIMES`. Submitted array order never
proves chronology; an out-of-order array is reported separately.

If `policy.processing_time` is omitted, the latest declared `received_at` is
used. Supplying it makes future-event checks reproducible. The engine reports
future events, event-to-observation gaps, observation-to-receipt gaps, and a
processing time earlier than receipt. It never shifts timestamps or assumes
host clocks are synchronized.

## Identity and relationship rules

Process identity is `(host_id, process_instance_id)`. PID equality alone is
never identity and PID reuse is reported. A process instance declared on
multiple hosts is contradictory and receives no cross-host identity edge.
Explicit parent identity requires one matching start event on the same host;
otherwise the graph contains no invented parent node.

File identity is only `(host_id, declared path)` and is therefore weak. Rename
continuity uses the declared destination path, but no persistent physical-file
ID exists in schema 1.0.0. Same path on another host is unrelated.

Network identity requires host, protocol, local and remote endpoints, and an
explicit process-instance ID. Schema 1.0.0 has no persistent connection ID, so
even a complete matching tuple is weak and bounded by the window. A tuple
without process identity is not merged; a tuple can be reused.

Configuration events gain context only through an explicit process-instance
identity and temporal position. A reported startup, service, task, or registry
change is not automatically persistence or malicious activity.

Generated relationship types are `precedes`, `same_process_instance`,
`parent_process`, `same_declared_file`, `same_declared_connection`, and
`within_time_window`. `follows` is part of the contract vocabulary for clients
but the graph emits the equivalent forward `precedes` direction rather than a
reverse duplicate that could look cyclic. Every edge carries source and target
event UUIDs, evidence, confidence, state, window assessment, limitations, and
`causal: false`.

## Windows, confidence, and unknowns

The default window is 300 seconds and the maximum accepted window is 86,400
seconds. Identity candidates separated by more than the configured window are
not joined into an identity sequence. Window membership is a temporal fact,
not evidence of causality.

Confidence is categorical: `strong`, `weak`, or `indeterminate`; there is no
numeric score. State vocabulary distinguishes `established`,
`plausible_unverified`, `insufficient_evidence`, `contradictory_evidence`, and
`not_related`. The bounded graph contains justified positive edges; absent,
insufficient, outside-window, and contradictory cases are represented by
issues rather than quadratic negative edges. A missing start, parent, file
operation, or network state means only that it is absent from this batch.

## Determinism and limits

Duplicate UUIDs collapse to one canonical node. Conflicting duplicates produce
an error issue. Relationship and sequence UUIDs are UUIDv5 values derived from
their semantic type and member event IDs. Nodes, edges, sequences, and issues
use stable canonical ordering. Reordering input changes only trace metadata
about submission order and existing 05.02 validation observations, not the
canonical graph.

Hard limits include 256 input events, 512 KiB request bodies, 1,024 edges, 16
incident relationships per event, 128 sequences, 64 events per sequence, 512
issues, a one-second in-process evaluation budget, and 512 KiB serialized
output. Grouping and adjacent linking avoid all-pairs and exponential search.

## Privacy and operational boundary

Nodes expose event IDs, family, and timestamps. Evidence describes equality or
presence facts without echoing command lines, user names, paths, host IDs, or
network endpoints. Logs contain exception types only. Real telemetry can still
be sensitive, so authentication, authorization, transport security, rate
limits, and deployment-level concurrency/memory controls remain required.

## Example interpretation

Given a process start at `12:00:00Z`, a file modification attributed to the
same process at `12:00:02Z`, and its termination at `12:00:05Z`, the graph can
establish two adjacent `same_process_instance` edges and factual temporal
precedence. It can say that the three declarations form one bounded process
sequence. It cannot say the process caused the file change, that the file is
malicious, or that an ATT&CK technique occurred. If the file event omits its
process identity, temporal proximity alone remains indeterminate.
