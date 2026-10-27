# Phase 05 / Checkpoint 05.07.2 — Residual Security and Concurrency Remediation

Date: 2026-10-26 (America/Managua)

Branch: `main`

Base HEAD and `origin/main`: `b821eb9e2f71967de8fdff0e87351c4a84d0102b`

Status: **PASS as remediation — ready for independent final reaudit**

## A. Initial Audit

The working tree already contained two uncommitted audit artifacts:

- modified `docs/PHASE_05_AUDIT_REPORT.md`;
- untracked `docs/PHASE_05_INDEPENDENT_REAUDIT.md`.

Both were preserved. HEAD and `origin/main` matched at `b821eb9`; the branch was
`main`. Metadata remained `0.4.1`, the newest tag remained `v0.4.0`, and no tag
`v0.4.1` existed.

The incoming gate was 908 tests and 94.50% coverage. The independent reaudit had
returned **PARTIAL** for two findings:

1. P05-SEC-001: the default loader verified the artifact, but
   `load_snapshot(path, expected_artifact_digest=None)` accepted mutated bytes and
   `ATTACKCatalogStore.publish()` accepted an unverified snapshot.
2. P05-CONC-003: normal drain and ownership worked, but cancelling the `aclose()`
   waiter left `shutdown_complete=False`, the executor open and a worker alive
   until a second close call.

Both defects were reproduced deterministically before remediation. No Git
mutation, branch, tag, Phase 06 feature, rule change, ATT&CK policy change,
malware conclusion or telemetry persistence was introduced.

## B. Security Trust Boundary

The production API no longer accepts a caller-selected or disabled digest:

- `build_snapshot_from_stix()` removes `expected_source_digest` and always pins
  `ATTACK_SOURCE_SHA256`;
- `load_snapshot()` removes `expected_artifact_digest` and delegates to
  `load_verified_snapshot()`;
- `VerifiedAttackCatalogSnapshot` hashes the compressed bytes and compares them
  with the repository artifact pin using `hmac.compare_digest` before gzip, JSON
  or schema parsing;
- `ATTACKCatalogStore.load()` uses only the verified path;
- `ATTACKCatalogStore.publish()` requires the exact verified type, rechecks the
  pin and only then assigns the snapshot atomically;
- unverified fixture construction and loading are private
  (`_build_fixture_snapshot_from_stix`, `_load_fixture_snapshot`) and the runtime
  never calls them.

The exact-type check blocks a subclass from being used to spoof publication.
The public fixture path cannot be published. A failed load leaves the previous
valid catalog in place.

Reproduction after remediation:

```text
official artifact: 916eabb166a794e881f23be2fe9bf5590bdba5117db892fc405af636eaa0bc88
load_snapshot(expected_artifact_digest=None): TypeError
build_snapshot_from_stix(expected_source_digest=None): TypeError
load_verified_snapshot(mutated): REJECT (artifact digest)
load_snapshot(mutated): REJECT (artifact digest)
publish(unverified fixture): REJECT
```

The artifact pin remains a repository-version integrity control, not a
third-party MITRE signature. Simultaneous compromise of code and artifact is
outside this model.

## C. Cancellation-Safe Shutdown

`SynchronousWorkerManager` now owns one internal close task rather than relying
on each caller's coroutine:

1. `_start_close()` creates and registers the task under the state lock, sets
   `_closed=True` synchronously and returns the same task to every caller.
2. `aclose()` awaits that task through `asyncio.shield`, so cancelling one,
   several or every waiter cannot cancel the shared drain.
3. `_release_worker()` is idempotent and is used by both the worker completion
   callback and the close path, avoiding double release.
4. Late worker exceptions are consumed by the completion callback.
5. `_close_impl()` snapshots owned futures, drains them outside the lock, calls
   `shutdown(wait=True, cancel_futures=False)`, verifies zero owned/active
   workers and then sets `shutdown_complete=True`.
6. `shutdown_complete` is a public read-only property.

Final reproduction with one resistant worker and three cancelled waiters:

```text
after all waiters cancelled: closed=True, shutdown_complete=False,
  active=1, owned_workers=1, executor_shutdown=False
after worker release: shutdown_complete=True, active=0,
  owned_workers=0, executor_shutdown=True
```

The final state was reached without a second `aclose()` call.

Documented semantics: cancelling a task before its coroutine's first step means
close never started; no state was mutated and the caller may retry. Python
threads cannot be force-killed, so shutdown waits for real completion. A
non-cooperative worker can delay shutdown indefinitely; forced termination would
require process isolation.

## D. Automated Coverage

`tests/test_phase05_security_remediation_0572.py` adds 26 tests:

- catalog: forbidden digest parameters, five semantic mutations, corrupt/empty/
  truncated input, single-byte change, unverified publication, subclass spoofing,
  verified-bytes construction, failed-load preservation, repeated loads,
  packaged resource and application composition;
- workers: close without workers, cancellation of the first/second/remaining/all
  waiters, immediate cancellation, cancellation before the first coroutine step,
  late worker failure, resistant worker, four workers plus fifth rejection, and
  the shared manager.

Results:

- affected ATT&CK/security suites: **84 passed** (42 + 16 + 26);
- Phase 05 focused suite with `PYTHONASYNCIODEBUG=1` and warnings as errors:
  **228 passed**;
- full suite: **934/934 passed**.

## E. Distribution Verification

A prepared copy of the working tree was built in isolation. Because no commit was
allowed, this was not a `git archive HEAD` build; the definitive build must be
repeated from the clean commit that records these files. Build isolation
installed setuptools 84.2.1, so the build environment itself was not offline.

| Artifact | Size | Snapshot | Snapshot SHA-256 |
|---|---:|---|---|
| `icylens_api-0.4.1-py3-none-any.whl` | 1,726,161 bytes | present | `916eabb1...a0bc88` |
| `icylens_api-0.4.1.tar.gz` | 1,771,175 bytes | present | `916eabb1...a0bc88` |

Both archives contain the 1,541,193-byte snapshot. The sdist includes the new
test file. The wheel contains the private fixture helpers and no public
`load_fixture_snapshot`.

The wheel was installed non-editably into a temporary target outside
`C:\icylens`. Running from that target:

```text
app_file: ...\p0572_install\app\__init__.py
version: 0.4.1
artifact: 916eabb166a794e881f23be2fe9bf5590bdba5117db892fc405af636eaa0bc88 1541193
stats: 26086 15 858 493 21262
T1059: Command and Scripting Interpreter active
installed catalog load: PASS
```

`pip check` passed for the installed target.

## F. Cross-Module Regression

The complete gate re-exercised Phase 05 and the earlier phases. No rule,
mapping policy, uncertainty contract, scientific boundary, public route or
response model was intentionally changed.

P05-REL-002 (wheel/sdist resource and offline installed load) and P05-PRIV-004
(real redaction) remain **FIXED** with no regression. The only programmatic API
tightening is the removal of the digest-disable parameters and the unverified
public fixture helper names.

## G. API and OpenAPI

OpenAPI returned HTTP 200 with 33 paths. The behavior analysis, behavior-to-
ATT&CK mapping and ATT&CK status paths were present. HTTP paths and methods are
unchanged. Request/response bounds, strict schemas, typed uncertainty states and
sanitized error handling remain intact.

## H. Quality Gate

| Check | Result |
|---|---|
| Ruff lint | PASS |
| Ruff format | PASS — 159 files |
| mypy strict | PASS — 132 source files |
| pytest | PASS — 934/934 |
| statement/branch coverage | PASS — 94.51% |
| `pip check` | PASS |
| Unified Quality Gate | PASS |

The configured 85% threshold was not changed. `git diff --check` reported no
errors (only Windows CRLF notices).

## I. Findings Register

### P05-SEC-001

- Severity: High.
- Files: `apps/api/app/attack/catalog.py`, affected tests.
- Original residual: runtime digest could be disabled and store publication did
  not authenticate the artifact.
- Correction: non-bypassable artifact pin before parse; verified-only load and
  publication; private fixture helpers.
- Evidence: mutated/corrupt bytes rejected; forbidden keyword arguments raise
  `TypeError`; unverified publication raises `TypeError`; installed wheel loads
  the official catalog offline.
- Status: **FIXED**.
- Residual: pin is not a third-party signature; code and artifact compromise is
  outside the model.

### P05-CONC-003

- Severity: Medium.
- Files: `apps/api/app/services/synchronous_workers.py`, affected tests.
- Original residual: cancelling `aclose()` left shutdown incomplete and the
  executor open.
- Correction: one registered internal close task, shielded waiter, idempotent
  release, exception consumption, zero-worker verification and
  `shutdown_complete`.
- Evidence: all waiters cancelled, worker released, executor shut down and
  completion reached without a second call; resistant worker blocks truthfully.
- Status: **FIXED**.
- Residual: no forced thread termination; process isolation is required for that
  guarantee.

### P05-REL-002 and P05-PRIV-004

Both remain **FIXED**. The wheel/sdist and offline installed-load evidence were
repeated, and the full gate re-exercised redaction and distribution tests.

### Open residual risks

| Finding | Status | Note |
|---|---|---|
| P05-REL-005 | OPEN | Metadata is `0.4.1`; no `v0.4.1` tag |
| P05-REP-006 | OPEN | No lockfile with reproducible hashes |
| P05-DEPLOY-007 | LIMITATION | Public production deployment remains out of scope |

## J. Final Decision

Checkpoint 05.07.2: **PASS as remediation**.

P05-SEC-001 and P05-CONC-003 are corrected and covered by adversarial tests.
This is not Phase 05 final acceptance. No `docs/PHASE_05_ACCEPTANCE.md` was
created, no tag was created or moved, and Phase 06 was not started.

Phase 05 acceptance remains **BLOCKED pending independent final reaudit** on a
clean commit containing these changes. Public production readiness remains
**NOT READY**.

## K. Git Handoff

Modified:

- `apps/api/app/attack/catalog.py`
- `apps/api/app/services/synchronous_workers.py`
- `apps/api/tests/test_attack_knowledge.py`
- `apps/api/tests/test_phase05_security_remediation.py`
- `docs/PHASE_05_AUDIT_REPORT.md` (append-only checkpoint section)

Created:

- `apps/api/tests/test_phase05_security_remediation_0572.py`
- `docs/PHASE_05_CHECKPOINT_05_07_2_REMEDIATION.md`

Preserved but not committed:

- `docs/PHASE_05_INDEPENDENT_REAUDIT.md` (pre-existing untracked file, appended)

No `git add`, commit, push, tag, branch or force operation was performed.
Suggested commit sequence:

```text
fix(attack): remove digest bypass from catalog trust boundary
fix(workers): make synchronous worker shutdown cancellation-safe
test(security): cover checkpoint 05.07.2 adversarial cases
docs(audit): record checkpoint 05.07.2 remediation
```

## L. Reaudit Recommendation

Rebuild from the clean commit that records these files, then repeat:

1. call `load_snapshot` and `build_snapshot_from_stix` with the removed digest
   keywords and confirm `TypeError`;
2. load mutated, corrupt, truncated and single-byte-altered artifacts and confirm
   rejection before publication;
3. confirm unverified fixture snapshots and subclasses cannot be published;
4. cancel one and all `aclose()` waiters, release a resistant worker and confirm
   `shutdown_complete=True`, zero active/owned workers and executor shutdown;
5. inspect wheel and sdist for the 1,541,193-byte snapshot and digest;
6. install the wheel outside the checkout and load ATT&CK 19.2 offline;
7. run the complete Quality Gate with unchanged thresholds.

Only that independent re-run can change the Phase 05 final decision.

## M. Next

Next checkpoint: independent final reaudit of Phase 05.

Phase 06 — Multilayer Correlation & Explainability — was not started.

## N. Post-Checkpoint Correction - 2026-10-26

The independent reaudit in `PHASE_05_INDEPENDENT_REAUDIT.md` section R found a
residual P05-SEC-001 bypass in this checkpoint: `publish()` trusted the cached
`_snapshot` after verification. Section R remains the historical verdict.

The follow-up correction makes `publish()` derive a fresh snapshot from the
pinned artifact on every publication and blocks normal mutation of the verified
object. The checkpoint suite is now **29 passed**; the focused Phase 05 suite is
**231 passed**; the full gate is **937 passed** at **94.49%** coverage. The
corrected wheel and sdist contain the pinned 1,541,193-byte artifact and were
installed non-editably outside the checkout for a smoke test.

P05-CONC-008 remains a reviewed, low-severity lifecycle residual: a cancelled
lifespan exit can skip non-worker `aclose()` calls after the worker manager has
drained. It is not part of this security correction.

Phase 05 final acceptance remains **BLOCKED** pending a new independent audit of
a clean commit. No `PHASE_05_ACCEPTANCE.md`, tag, commit, push, branch or release
was created, and Phase 06 remains **NOT AUTHORIZED**.
