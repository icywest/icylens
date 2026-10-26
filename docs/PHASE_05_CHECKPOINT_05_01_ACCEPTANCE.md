# Phase 05 checkpoint 05.01 acceptance

## Decision

PASS. The Enterprise ATT&CK 19.2 knowledge foundation is versioned, locally
available, immutable to consumers, bounded, read-only, and separated from any
detection claim. The final quality-gate evidence is recorded in the development
log and checkpoint handoff.

## Acceptance evidence

- Official MITRE `attack-stix-data` STIX 2.1 source fixed to tag `v19.2`.
- Raw SHA-256 verified as
  `dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4`.
- 26,086 objects validated before a 15-tactic, 858-technique,
  493-sub-technique, 21,262-relationship snapshot was published.
- STIX/external identities, domains, tactic phases, explicit parent
  relationships, references, versions, platforms and lifecycle states remain
  typed and distinguishable.
- Historical objects remain available only through explicit opt-in.
- Runtime lookup loads the packaged artifact and performs no network request.
- Download/update is a deliberate bounded CLI operation and atomically
  publishes only after complete validation.
- Six GET-only endpoints expose status, tactics, tactic techniques, techniques,
  and sub-techniques with strict ID validation and bounded pagination.
- Offline synthetic/adversarial tests cover valid records, missing optional
  fields, Unicode, malformed/corrupt/oversized structures, duplicates, domain
  and relationship failures, immutability, rollback prevention, unavailable
  state, OpenAPI, invalid inputs, methods, and the packaged official artifact.
- Final gate: 748 tests, 93.63% branch coverage, Ruff lint/format PASS, mypy
  strict PASS, pip check PASS, and overall quality gate PASS.

## Boundaries and known risks

The repository pin verifies reproducibility, not independent publisher
authenticity. The snapshot does not expose arbitrary full-text search or raw
relationship queries. The legacy data-source model is not a dependency. No
CVE/CWE/EPSS/KEV/ML association and no behavioral detection is implemented.
ATT&CK 20.0 was already listed on 26 October 2026; 19.2 remains intentionally
fixed for this checkpoint and requires an explicit reviewed update later.

