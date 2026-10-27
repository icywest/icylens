# Phase 05 Final Acceptance

**Decision: ACCEPTED - Educational Local Readiness READY WITH CONDITIONS**

**Public Production Readiness: NOT READY**

- Date: 2026-10-26
- Repository: `C:\icylens`
- Branch: `main`
- Accepted commit: `fd922310db1c723588ff66f95d08a4d0df7fc9d1`
- Upstream: `origin/main` at the same commit; divergence `0/0`
- Tracked working tree: clean before this acceptance record
- Application version: `0.4.1`
- Release tag: none for `0.4.1`; latest existing tag is `v0.4.0`

## Scope

This acceptance covers the Phase 05 backend at the accepted commit and artifacts
built exclusively from that commit. It verifies the security, lifecycle, privacy,
packaging, and regression corrections from the Phase 05 remediation cycle.

No functional code, tests, or quality thresholds were changed during this
audit. No commit, tag, branch, push, or release action was performed.

## Git provenance

The accepted commit contains the corrective sequence:

```text
9174436 fix(attack): derive published catalog from verified artifact
ce1892a fix(workers): make synchronous worker shutdown cancellation-safe
2021519 test(security): cover verified catalog publication and shutdown
fd92231 docs(audit): record final phase 05 remediation evidence
```

The corrective tests and remediation reports are tracked at the accepted commit.
`git diff --check` passed and `git rev-list --left-right --count HEAD...origin/main`
returned `0 0`.

## Clean artifact build

Artifacts were built from `HEAD:apps/api` through a clean Git archive using
`git -c core.autocrlf=false archive`. No working-tree source was used. The archive
bytes for `catalog.py`, `synchronous_workers.py`, `pyproject.toml`, and the pinned
ATT&CK snapshot matched `git show HEAD`. The build ran in isolation with
`python -m build`.

| Artifact | Size | SHA-256 |
|---|---:|---|
| Wheel | 1,726,420 bytes | `DF2B7241456B657A3F0EF5B88E447162622040FCE5727D5BE31221FF4D5BC681` |
| Sdist | 1,768,561 bytes | `3D2FE5BAEE1B06FC2B0A3F8129F890372F5BA19709E56040EFFC8882347DA885` |

Both archives contain:

- `catalog.py` SHA-256
  `1de36702df5b66c367e88a837fa0d0220674bb86de65839e8f28df18ad411f15`
- `synchronous_workers.py` SHA-256
  `22eba2a44725cc703713beeda91f06ffab66bc7c2d610043c020da711de45546`
- ATT&CK snapshot: 1,541,193 bytes, SHA-256
  `916eabb166a794e881f23be2fe9bf5590bdba5117db892fc405af636eaa0bc88`

The sdist includes the Phase 05 regression tests and `MANIFEST.in`; the wheel does
not contain tests. Metadata identifies `icylens-api 0.4.1`, Python
`>=3.12,<3.14`, and 13 runtime dependencies. The build emitted a non-blocking
warning that the sdist lacks a standard `README` file; this did not affect the
wheel, installation, tests, or security behavior.

## Isolated installation

The clean wheel was installed non-editably outside the checkout. The imported
`app` and ATT&CK data resolved inside the installation target, not the source
tree.

Observed application behavior:

- Version: `0.4.1`
- ATT&CK: `19.2`
- Techniques: `858`
- Tactics: `15`
- Relationships: `21,262`
- `T1059`: `Command and Scripting Interpreter`
- OpenAPI: HTTP `200`, `33` paths
- Status and technique endpoints: successful

The install therefore operates without the checkout and without downloading the
ATT&CK dataset.

## Security and lifecycle verification

### P05-SEC-001 - corrected

Runtime checks on the installed wheel confirmed:

```text
normal assignment: REJECT VerifiedAttackCatalogSnapshot is immutable
cached snapshot after mutation: TAMPERED AFTER VERIFICATION
published T1059: Command and Scripting Interpreter
mutated artifact publish: REJECT Snapshot artifact digest does not match the pin
```

The published catalog is derived from the pinned artifact rather than the
caller-visible cached snapshot. Post-verification mutation cannot alter published
content.

### P05-CONC-003 - corrected

The installed wheel was exercised with a timeout and with cancelled waiters:

- Timeout was observed with active and owned worker counts correct.
- Cancelled waiters left the close operation incomplete but manager-owned.
- The first close completed after worker release with
  `shutdown_complete=True`, `active=0`, `owned=0`, and the executor shut down.
- A second `aclose()` was not required; repeated `aclose()` was idempotent.

### P05-PRIV-004 - corrected

Privacy canaries were absent from responses and logs for:

- `POST /api/v1/behavior/rules/evaluate`
- `POST /api/v1/behavior/analyze`
- `POST /api/v1/behavior/attack/map`
- `GET /api/v1/attack/status`

All four requests returned HTTP `200`; captured application logs contained no
canary values.

### P05-CONC-008 - accepted low-severity residual, not fixed

When the lifespan exit task is itself cancelled, the shielded worker manager
still completes, but later non-worker `aclose()` calls are skipped:

```text
manager complete True
resource closes after cancelled lifespan []
resource closes after explicit cleanup ['kev_store', 'epss_service', 'kev_client', 'nvd_client']
```

This is a process-lifecycle residual. It does not leak workers or bypass worker
ownership. It is accepted only for Educational Local Readiness, where shutdown
normally terminates the process. It is not fixed and must be remediated before
any public or production deployment claim.

## Regression gate

The official `scripts/quality_gate.py` passed on the accepted tree:

- Pytest: **937 passed**
- Branch coverage: **94.49%**, threshold unchanged at 85%
- Ruff lint and format: PASS
- mypy strict: PASS
- `pip check`: PASS

```text
QUALITY GATE: PASS
```

## Finding disposition

| Finding | Disposition |
|---|---|
| P05-SEC-001 | Corrected and closed; artifact-derived publication prevents cached-snapshot substitution |
| P05-REL-002 | Closed for the accepted clean artifacts; pinned dataset is packaged and loads offline |
| P05-CONC-003 | Closed for synchronization and worker ownership; cancellation-safe drain verified |
| P05-PRIV-004 | Closed; canaries absent from endpoints, serialized results, status, and logs |
| P05-CONC-008 | Accepted as Low residual for local educational use only; **not fixed** |

## Final decision

**Educational Local Readiness: READY WITH CONDITIONS.**

Conditions:

1. Use is limited to educational, laboratory, or local deployment.
2. The accepted baseline is commit
   `fd922310db1c723588ff66f95d08a4d0df7fc9d1` and its reproducibly built
   artifacts described above.
3. P05-CONC-008 remains an accepted low-severity lifecycle residual; a cancelled
   lifespan in a continuing process may skip non-worker client cleanup.
4. Public or production exposure requires P05-CONC-008 remediation and a separate
   production-readiness review.

**Public Production Readiness: NOT READY.**

It is appropriate to prepare the `v0.5.0` release from this accepted baseline.
This document does not create or authorize that tag. Phase 06 has not been
started.
