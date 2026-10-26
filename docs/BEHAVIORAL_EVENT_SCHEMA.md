# Behavioral event schema

Phase 05 checkpoint 05.02 defines a canonical, descriptive event contract. A
structured event records declared or synthetic telemetry; it is not proof of
malware, compromise, intent, or execution of a MITRE ATT&CK technique.

## Common envelope and provenance

Every process, file, network, and configuration record has a UUID `event_id`,
discriminated `event_type`, timezone-aware UTC-normalized event `timestamp`,
bounded `host_id`, structured `source`, declared `platform`, schema version
`1.0.0`, explicit `synthetic` flag, provenance, and bounded JSON `attributes`.
Unknown event fields are rejected.

Provenance separately records the source identifier, observation time,
receipt/generation time, `synthetic` or `declared` nature, missing fields, and
limitations. Receipt cannot precede observation, observation cannot precede
event time, source identities must agree, and a synthetic flag must agree with
the provenance nature. Structured data receives no implicit confidence score.

## Event families

- `ProcessEvent` records `start` or `terminate`, a UUID process-instance
  identity, PID, process start time, executable path, optional command line,
  user, parent identity, and exit code. PID equality never establishes a
  parent-child relationship across hosts or process instances.
- `FileEvent` records create, modify, delete, or rename with descriptive paths,
  an optional destination, optional declared SHA-1/SHA-256 values, and optional
  process identity. It never opens a path or calculates a real file hash.
- `NetworkEvent` distinguishes attempted, established, and closed states and
  validates IPv4/IPv6 addresses, ports, protocol, and optional process identity.
  An attempt is not promoted to an established connection.
- `ConfigurationEvent` describes a reported registry, service, scheduled-task,
  or startup change with prior/current declared values. It performs no host
  configuration operation.

## Structural and batch validation

Pydantic validates identities, UTC timestamps, discriminators, enums, IPs,
ports, field combinations, lengths, nested attributes, and serialized event
size. Batch validation then reports duplicate event identities, order problems,
process/host/parent/lifecycle contradictions, file transitions, and network
state transitions. Warnings such as a missing creation earlier in the same
batch describe limited context rather than attacks. Missing optional values stay
`null` and can also be named explicitly in provenance.

Hard limits are 256 events, 32 KiB per serialized event, 512 KiB per validation
body, four nested attribute levels, 64 items per attribute collection, and
4,096 characters per generic attribute string. Request-body limits execute in
ASGI middleware before FastAPI buffers JSON. Events are never persisted.

