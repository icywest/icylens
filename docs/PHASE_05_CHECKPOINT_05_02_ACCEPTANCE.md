# Phase 05 checkpoint 05.02 acceptance

## Decision

PASS. iCYLENS now has strict canonical contracts for four behavioral telemetry
families, explicit provenance, semantic batch validation, and an offline
deterministic educational generator. No detection or ATT&CK mapping is present.

## Acceptance evidence

- Process, file, network, and configuration models use a shared typed envelope
  without flattening family-specific fields.
- Event and ingestion times remain distinct and UTC-normalized; missing fields,
  synthetic nature, and limitations are explicit.
- Validation checks identifiers, order, host/process consistency, IPs, ports,
  enums, contradictory transitions, duplicate identities, depth, lengths,
  counts, and serialized sizes.
- All ten required benign/abstract scenarios are deterministic from explicit
  seed/configuration and retain consistent host/process identities where the
  scenario is intended to be coherent.
- Three typed endpoints validate batches, generate scenarios, and publish hard
  schema limits without persistence, executable uploads, streaming ingestion,
  background workers, host operations, or network access.
- Tests cover all event families, IPv4/IPv6, invalid values, scenario
  determinism, different seeds, contradictions, size limits, absence of I/O,
  sanitized errors, OpenAPI, and regressions through 05.01 and Phase 04.

Final quality evidence: 795 tests passed, 93.89% branch coverage, Ruff
lint/format PASS, mypy strict PASS, `pip check` PASS, unified Quality Gate PASS,
and `git diff --check` PASS.

## Boundaries

Validation is limited to declared facts and relationships visible inside one
request batch. It cannot establish endpoint truth or malicious intent. Events
are not mapped to ATT&CK techniques, CVEs, CWEs, KEV, EPSS, or ML results. The
generator is not an EDR and supplies no detection efficacy evidence.

