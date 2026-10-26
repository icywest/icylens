# Deterministic synthetic telemetry generator

The offline generator accepts an explicit scenario ID, integer seed, platform,
UTC start time, and bounded event count. UUIDv5 identities, host/process
identities, paths, values, ordering, and timestamps derive only from that input.
Identical configuration produces an identical response; `generated_at` is also
derived from the requested timeline rather than the wall clock.

The ten educational scenario kinds are:

1. Normal process start and termination.
2. File creation and modification.
3. Network attempt followed by establishment.
4. Reported configuration change.
5. Incomplete process sequence.
6. Out-of-order events.
7. Duplicate event identities.
8. Inconsistent process-parent declarations.
9. Explicitly missing optional fields.
10. Contradictory network state.

Paired coherent scenarios require an even count; ordering and duplicate
scenarios require at least two events. Generation is capped at 100 events and
the request body at 64 KiB. It accepts no output path, reads no file, opens no
network connection, executes no command, and creates no resident process.

Inconsistent scenarios intentionally return ordinary typed events plus
validation issues. They are not labeled as malicious and contain no malware
payloads or technique names. The output disclaimer states that it is synthetic
educational telemetry, not an endpoint observation or threat detection.

Example:

```json
{
  "scenario_id": "training-demo",
  "scenario_kind": "network_attempt_established",
  "seed": 42,
  "platform": "linux",
  "start_time": "2026-10-26T12:00:00Z",
  "event_count": 2
}
```

POST this contract to `/api/v1/behavior/scenarios/generate`. The endpoint is a
pure request/response operation; it does not save the request or result.

