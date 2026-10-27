# Phase 05 / Checkpoint 05.07.1 — Security Remediation

Date: 2026-10-26 (America/Managua)

Branch: `main`

Base HEAD and `origin/main`: `8fbfbd3d917e445a0d53404865d960cdbe7d985a`

Status: **PASS — ready for independent final reaudit**

## A. Initial Audit

The initial working tree contained the pre-existing untracked
`apps/api/app/attack/__init__.py` and the new untracked
`docs/PHASE_05_AUDIT_REPORT.md`. `main`, HEAD and `origin/main` matched. Runtime,
package and OpenAPI metadata remained `0.4.1`; `v0.4.0` remained the newest tag
and no `v0.4.1` existed. No lockfile was present.

The incoming gate was 892 tests and 94.43% coverage. All four original findings
were reproduced before remediation: semantically altered snapshot accepted,
snapshot absent from wheel, lost cleanup ownership/capacity after shutdown
cancellation, and sensitive value returned with `redacted=true`.

No Git mutation, branch, tag, Phase 06 feature, new rule, ATT&CK policy, malware
detection or telemetry persistence was introduced.

## B. Root Causes

| Finding | Root cause |
|---|---|
| P05-SEC-001 | Runtime compared self-declared source provenance, not the bytes of the serialized artifact it consumed. |
| P05-REL-002 | Package discovery/data configuration did not declare the snapshot; editable execution masked the omission. |
| P05-CONC-003 | Timeout/cancellation created an unreferenced asyncio cleanup task; lifespan owned neither it nor the underlying synchronous work. |
| P05-PRIV-004 | `redacted` was metadata only; `_field()` retained the original value and did not classify network/source/host values uniformly. |

## C. ATT&CK Snapshot Integrity

Two independent constants are now maintained:

- source STIX digest:
  `dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4`;
- packaged artifact digest:
  `916eabb166a794e881f23be2fe9bf5590bdba5117db892fc405af636eaa0bc88`.

`load_snapshot()` performs bounded artifact read, digest comparison, bounded gzip
expansion, JSON/schema validation, provenance pin validation, identity/reference
validation and only then returns a candidate. `ATTACKCatalogStore.load()` still
publishes only after the complete operation succeeds, so a failed replacement
does not displace an existing valid snapshot.

Adversarial coverage modifies technique name/status, relationship type, tactic
name and provenance; it also tests a single compressed-byte change, truncation,
corrupt gzip, excessive compressed/expanded data, missing file and failed
replacement. Every altered packaged artifact is rejected before promotion.

The artifact digest is a repository-version integrity pin, not MITRE-authenticated
signing. Simultaneous compromise of code and artifact remains outside this model.

## D. Distribution Reproducibility

The selected policy is regular Python packages:

- `app.attack/__init__.py` is part of the required handoff;
- package discovery explicitly sets `namespaces=false`;
- `app.attack.data/__init__.py` defines the resource package;
- package data declares `*.json.gz`;
- `MANIFEST.in` includes the snapshot for sdist;
- runtime default loading uses `importlib.resources`.

Prepared-tree build results:

| Artifact | Size | Snapshot | Snapshot SHA-256 |
|---|---:|---|---|
| `icylens_api-0.4.1-py3-none-any.whl` | 1,725,078 bytes | present | `916eabb1…a0bc88` |
| `icylens_api-0.4.1.tar.gz` | 1,672,353 bytes | present | `916eabb1…a0bc88` |

The wheel contains both package `__init__.py` files and the 1,541,193-byte
snapshot. A non-editable install in an isolated temporary venv ran from outside
`C:\icylens`; `app.__file__` resolved inside that venv. Without accessing the
checkout or network, it loaded version 19.2, 26,086 objects, 15 tactics, 858
techniques, 493 sub-techniques and 21,262 relationships, then resolved active
`T1059`. Installed package version was `0.4.1`; `pip check` passed.

Build isolation downloaded setuptools 84.2.1. Therefore the build itself was not
claimed offline. The installed catalog smoke test was offline and used already
available runtime dependencies. Exact dependency reconstruction remains limited
by the existing absence of a lockfile.

The sdist build also emitted the pre-existing packaging warning that the backend
project directory has no local README. It did not affect metadata generation,
archive contents, installation or catalog loading, but should be resolved as a
separate release-documentation cleanup rather than folded into these four
security fixes.

## E. Worker Ownership

`SynchronousWorkerManager` owns a bounded `ThreadPoolExecutor`, the admitted
concurrent futures, capacity accounting, close state and drain. It does not use
detached supervisor tasks.

State semantics are:

1. admission increments capacity and registers the future atomically;
2. running work stays registered through request timeout/cancellation;
3. the future callback observes the exception/result and releases once on actual
   thread completion;
4. `aclose()` rejects new submissions and waits outside the state lock;
5. after drain it closes the executor and requires zero active/owned workers;
6. repeated `aclose()` is a no-op.

FastAPI stores one shared manager in `app.state`. Mapping standalone and unified
analysis reference that same owner, so their combined Phase 05 maximum is four,
not two independent groups of four. Lifespan drains it before closing other
application resources.

Tests exercise timeout, request cancellation, immediate shutdown, four active
workers, fifth rejection, completion during shutdown, worker exception, submit
failure rollback, closed admission, unbalanced release and idempotent shutdown.
There is no application queue and no cleanup supervisor to cancel before its
first cycle.

Residual limitation: Python cannot forcibly stop a running thread. Shutdown
waits for real completion and truthfully remains incomplete while a resistant
worker runs. Process isolation would be required for forced CPU termination.

## F. Privacy Redaction

`REDACTED_EVIDENCE_VALUE` is the single public replacement marker.
`EvidenceField` validates both directions: a redacted field must contain the
marker, and the marker requires `redacted=true`.

The rule engine now removes values for host ID, source ID, file path,
configuration target, sensitive command-line metadata and local/remote endpoints.
It preserves event UUID, rule identity/version, safe field name, nature,
structural booleans/actions, satisfied conditions and limitations.

Canary tests cover command line, secret token, executable path, username,
hostname, source/producer, file path, local/remote IP, port, registry target,
previous/current configuration values and arbitrary secret attributes. No canary
appears in engine JSON or `/behavior/rules/evaluate`; rule outcomes remain equal.

## G. Cross-Module Regression

The complete gate re-exercised 05.01–05.06, NVD/KEV/EPSS and vulnerability
correlation, Static Analysis and Synthetic ML. Enterprise ATT&CK remains 19.2,
the 16 revoked sub-technique fallback remains restricted, the twelve rules and
three mapping policies are unchanged, temporal relationships retain strength and
non-causality, and unified partial-result semantics remain intact.

No CVE/CWE/KEV/EPSS/ML-to-ATT&CK inference, confirmed attack, malware conclusion,
causal claim or persistence was added.

## H. API and OpenAPI

Affected endpoint tests passed for rules evaluate, mapping, unified declared and
synthetic analysis, ATT&CK status and technique lookup. Paths and methods are
unchanged. Body/output bounds, strict schemas, typed states and sanitized
413/422/429/500/503 handling remain compatible.

The only intentional response tightening is that sensitive rule evidence values
are now actually replaced. OpenAPI continues to describe the same response model;
the model validator enforces its redaction semantics.

## I. Adversarial Tests

`tests/test_phase05_security_remediation.py` adds 16 deterministic tests/cases
covering artifact mutation, byte integrity, failed promotion, decompression,
privacy canaries, contract enforcement, capacity invariants, four-worker drain,
exceptions and FastAPI lifecycle/shared ownership.

Phase 05 focused execution with asyncio debug and warnings as errors completed:

```text
202 passed in 39.51s
```

The remediation file alone completed:

```text
16 passed in 9.33s
```

## J. Quality Gate

Final result:

| Check | Result |
|---|---|
| Ruff lint | PASS |
| Ruff format | PASS — 158 files |
| mypy strict | PASS — 132 source files |
| pytest | PASS — 908/908 |
| statement/branch coverage | PASS — 94.50% |
| `pip check` | PASS |
| Unified Quality Gate | PASS |

Coverage increased from the 94.43% baseline without changing the configured
85% threshold.

## K. Findings Register

### P05-SEC-001

- Severity: High.
- Files: `app/attack/catalog.py`, packaged snapshot.
- Original evidence: altered T1059 name loaded with original declared source
  digest.
- Correction: independent artifact pin verified before gzip/parse.
- Adversarial result: all semantic and byte mutations rejected; valid resource
  loads; failed replacement preserves prior snapshot.
- Status: **FIXED**.
- Residual: no third-party signature if code and artifact are both compromised.

### P05-REL-002

- Severity: High.
- Files: `pyproject.toml`, `MANIFEST.in`, both ATT&CK package initializers,
  resource loader.
- Original evidence: clean wheel omitted the snapshot.
- Correction: regular packages, explicit wheel/sdist data and resource loading.
- Adversarial result: archive inspection and non-editable off-checkout smoke test
  reproduced digest, version, counts and T1059.
- Status: **FIXED**.
- Residual: clean committed build must be repeated after handoff; dependency
  resolution itself is not locked/offline reproducible.

### P05-CONC-003

- Severity: Medium.
- Files: `app/services/synchronous_workers.py`, both Phase 05 services/routes and
  `app/main.py`.
- Original evidence: finished thread with `capacity.active == 1` after cleanup
  supervisor cancellation.
- Correction: concurrent-future ownership without detached supervisor, shared
  budget and lifespan drain.
- Adversarial result: zero active/owned futures after drains; fifth rejected;
  exceptions observed; debug/warnings clean.
- Status: **FIXED**.
- Residual: resistant native/Python thread delays shutdown; no forced kill.

### P05-PRIV-004

- Severity: Medium.
- Files: `app/behavior/rule_engine.py`, `app/schemas/behavior_rules.py`.
- Original evidence: original path returned with `redacted=true`.
- Correction: centralized replacement plus contract validator.
- Adversarial result: all response/JSON canaries absent while four rules remain
  matched.
- Status: **FIXED**.
- Residual: incoming telemetry remains sensitive and requires local/authenticated
  deployment controls; this checkpoint addresses response minimization.

## L. Final Decision

Checkpoint 05.07.1: **PASS**.

All four blocking findings have implementation, adversarial and distribution
evidence sufficient for independent closure review. This is not Phase 05 final
acceptance; the required next action is an independent final reaudit.

Public production readiness remains **NOT READY** because authentication,
authorization, distributed quotas/state, deployment TLS controls and hard CPU
isolation remain outside the educational backend.

## M. Git Handoff

Created:

- `apps/api/MANIFEST.in`
- `apps/api/app/attack/data/__init__.py`
- `apps/api/app/services/synchronous_workers.py`
- `apps/api/tests/test_phase05_security_remediation.py`
- `docs/PHASE_05_CHECKPOINT_05_07_1_REMEDIATION.md`

The pre-existing untracked `apps/api/app/attack/__init__.py` must be included in
the regular-package commit.

Modified:

- ATT&CK catalog loader and packaging configuration;
- main lifespan and Phase 05 capacity wiring;
- standalone mapping and unified execution wrappers/routes;
- rule evidence schema/engine;
- affected ATT&CK, rule, mapping and unified tests;
- `docs/PHASE_05_AUDIT_REPORT.md`.

No file was intentionally deleted. No Git add, commit, push, tag or branch action
was performed.

Suggested commit sequence:

```text
fix(attack): verify packaged catalog artifact integrity
build(api): include ATT&CK snapshot in wheel and sdist
fix(behavior): own and drain synchronous analysis workers
fix(behavior): redact sensitive rule evidence values
test(security): reproduce phase 05 audit findings
docs(audit): record phase 05 security remediations
```

## N. Reaudit Recommendation

Proceed with an independent final Phase 05 reaudit after these files are recorded
in a clean commit. The reviewer should rebuild from that commit, repeat the
non-editable smoke test, rerun shutdown/cancellation tests, scan every rule
response for canaries and execute the complete gate.

Do not create `PHASE_05_ACCEPTANCE.md` or `v0.5.0` until that review passes.

## O. Next

Next checkpoint: independent final reaudit of Phase 05.

Phase 06 — Multilayer Correlation & Explainability — was not started.
