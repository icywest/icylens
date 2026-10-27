# iCYLENS v0.5.0 Release Preparation

**Status: PREPARED - RELEASE CHANGES UNCOMMITTED, TAG NOT CREATED**

- Date: 2026-10-27
- Branch: `main`
- Audited code baseline: `fd922310db1c723588ff66f95d08a4d0df7fc9d1`
- Current HEAD and `origin/main`: `a98dd12c9fd39a769bbe34bb25d739adef65b0da`
- Release commit: pending
- Proposed annotated tag: `v0.5.0`
- Python package version: `0.5.0`
- Phase 05 acceptance: [`PHASE_05_ACCEPTANCE.md`](PHASE_05_ACCEPTANCE.md)
- Educational Local Readiness: **READY WITH CONDITIONS**
- Public Production Readiness: **NOT READY**

This document prepares the v0.5.0 educational local release from the accepted
Phase 05 baseline. It does not create a commit, tag, branch, push, or release.

## Release summary

iCYLENS v0.5.0 packages the Phase 01-05 backend as an offline-oriented,
educational cybersecurity analysis platform. It provides bounded static
analysis, gated synthetic ML demonstration, vulnerability intelligence, and
behavioral analysis against a pinned MITRE ATT&CK 19.2 catalog.

The release is not an EDR, SOC, SIEM, malware sandbox, vulnerability scanner, or
production detection product. It does not provide endpoint agents, live
telemetry collection, autonomous response, or validated real-world malware
classifications.

## Acceptance and repository baseline

The accepted code baseline is commit
`fd922310db1c723588ff66f95d08a4d0df7fc9d1`. The acceptance record was committed
separately as `a98dd12c9fd39a769bbe34bb25d739adef65b0da`, which is the current
`HEAD` and `origin/main`, with divergence `0/0`. The Phase 05 acceptance decision
is:

- 937 tests passed;
- 94.49% branch coverage;
- ATT&CK integrity passed;
- wheel/sdist installation passed;
- worker ownership passed;
- privacy canaries passed;
- Educational Local Readiness **READY WITH CONDITIONS**;
- Public Production Readiness **NOT READY**.

`docs/PHASE_05_ACCEPTANCE.md` is tracked at `a98dd12`; the acceptance record is
versioned and ready to be tagged after the release commit. Historical tags
`v0.1.0` through `v0.4.0` are unchanged; no `v0.4.1` tag exists and no `v0.5.0`
tag has been created.

## Version alignment

The active version surfaces now identify `0.5.0`:

| Surface | Value |
|---|---|
| `apps/api/pyproject.toml` | `0.5.0` |
| `Settings.APP_VERSION` | `0.5.0` |
| `apps/api/.env.example` | `0.5.0` |
| Health response | `0.5.0` |
| OpenAPI `info.version` | `0.5.0` |
| Version and health tests | `0.5.0` |
| README configuration default | `0.5.0` |
| Architecture system overview | `0.5.0` |
| API contracts title and health example | `0.5.0` |

Historical documents that correctly record `0.4.1`, `0.4.0`, or earlier baselines
were intentionally not rewritten.

## Delivered scope

### Phase 01 - Backend foundation

FastAPI application factory, versioned `/api/v1` router, health and request
validation contracts, typed settings, logging, OpenAPI/Swagger/ReDoc, dependency
metadata, repository security tests, and the unified quality gate.

### Phase 02 - Static analysis

Bounded non-persistent upload validation, file fingerprinting, static content
inspection, indicator extraction, entropy and signature observations, and
unified static-analysis reporting. These are deterministic observations, not
malware verdicts.

### Phase 03 - Educational ML foundation

Dataset governance, bounded dataset construction, isolated train/validation/test
partitions, offline training and evaluation CLIs, and explicitly gated synthetic
demo inference. The demo is not a validated malware detector; probabilities are
not calibrated, and HTTP inference never trains or loads arbitrary serialized
models.

### Phase 04 - Vulnerability intelligence

Read-only NVD CVE integration, CVSS/CWE interpretation, CPE applicability,
CISA KEV snapshot intelligence, FIRST EPSS point intelligence, and unified
vulnerability correlation with explicit partial/unavailable states. No asset
scanning, exploitation, patching, or combined risk score is implemented.

### Phase 05 - Behavioral analysis and ATT&CK knowledge

Pinned offline Enterprise ATT&CK 19.2 catalog; strict behavioral telemetry
contracts and deterministic educational scenarios; twelve read-only behavioral
rules; bounded event-time correlation; conservative evidence-grounded ATT&CK
mapping; and privacy-minimized unified behavioral analysis. Catalog membership
is knowledge, not evidence that a behavior occurred.

## Phase 05 findings closed

| Finding | Disposition |
|---|---|
| P05-SEC-001 | Closed; publication derives the catalog from the verified pinned artifact and rejects cached-snapshot substitution |
| P05-REL-002 | Closed for produced artifacts; the pinned snapshot is packaged and loads offline |
| P05-CONC-003 | Closed for synchronization and worker ownership; cancellation-safe drain verified |
| P05-PRIV-004 | Closed; canaries absent from endpoints, serialized results, status, and logs |

### Release tag traceability

P05-REL-005 identified package metadata `0.4.1` without a matching tag. The
disposition is to skip `v0.4.1` and publish the next tag as `v0.5.0`; the
historical `v0.4.0` tag must remain unchanged. P05-REL-005 remains open until
the annotated `v0.5.0` tag is created.

## Residual risk

### P05-CONC-008 - Low - OPEN

**Status:** OPEN. **Classification:** Low. **Accepted only for the audited
educational local scope.**

If the lifespan exit task is cancelled, the worker manager still drains, but
later non-worker `aclose()` calls can be skipped in a process that continues:

```text
manager complete True
resource closes after cancelled lifespan []
resource closes after explicit cleanup ['kev_store', 'epss_service', 'kev_client', 'nvd_client']
```

This is not classified as fixed and must not be reclassified without new
evidence. It does not leak workers or bypass worker ownership. It must be
remediated before any public or production deployment claim.

## Educational scope and limitations

Accepted use is educational, laboratory, or local deployment. The following are
not provided:

- authentication, authorization, or multi-tenant isolation;
- database, durable job queue, report persistence, or distributed state;
- endpoint telemetry collection, EDR agent, live detection, or SOC workflow;
- dynamic malware execution, sandboxing, or automated containment;
- validated real-world malware detection or calibrated ML probabilities;
- asset scanning, exploitation, exploitation validation, or patching;
- production rate limiting, distributed caching, monitoring, or incident response;
- a dependency lockfile or bit-for-bit reproducible dependency closure;
- a frontend or production deployment topology.

External NVD, CISA KEV, and FIRST EPSS access is bounded and read-only. The
application remains dependent on those providers when their live features are
used. The default documentation and local Uvicorn command are not a production
security configuration.

## Artifact verification

Candidate artifacts were built from the prepared working tree with isolated
`python -m build`:

| Artifact | Size | SHA-256 |
|---|---:|---|
| Wheel | 1,726,482 bytes | `9CC3F31486C01792246BD98E891DA71A027A90E936C74BDCA8FDB0DD0356855F` |
| Sdist | 1,772,466 bytes | `33D6369D67D9D6F37A9967881229C1E646AC7AE121FE20546C947A152702C3E6` |

Both artifacts contain:

- package version `0.5.0`;
- corrected `catalog.py` SHA-256
  `1de36702df5b66c367e88a837fa0d0220674bb86de65839e8f28df18ad411f15`;
- corrected `synchronous_workers.py` SHA-256
  `22eba2a44725cc703713beeda91f06ffab66bc7c2d610043c020da711de45546`;
- ATT&CK snapshot `enterprise-attack-19.2.json.gz`, 1,541,193 bytes, SHA-256
  `916eabb166a794e881f23be2fe9bf5590bdba5117db892fc405af636eaa0bc88`.

The sdist includes the Phase 05 tests and `MANIFEST.in`; the wheel excludes
tests. The sdist emitted the existing non-blocking warning that no standard
README is present under `apps/api`.

Wheel and sdist installations were each installed non-editably outside the
checkout. Both reported version `0.5.0`, imported `app` from the installation
target, served health and OpenAPI version `0.5.0`, exposed 33 OpenAPI paths,
loaded ATT&CK 19.2 offline with 858 techniques, 15 tactics and 21,262
relationships, resolved `T1059`, and made no external network calls during
startup or API checks.

Because no release commit or tag was authorized during preparation, these are
candidate artifact hashes. After the release commit is created, rebuild from
that exact commit, archive the final wheel/sdist and their hashes, and confirm
the package contents and snapshot digest before tagging.

Suggested verification commands:

```powershell
Set-Location C:\icylens\apps\api
.\.venv\Scripts\python.exe -m build --outdir C:\icylens-release\v0.5.0
Get-ChildItem C:\icylens-release\v0.5.0 | Get-FileHash -Algorithm SHA256
.\.venv\Scripts\python.exe -m pip install --no-deps --target C:\icylens-release\install C:\icylens-release\v0.5.0\icylens_api-0.5.0-py3-none-any.whl
```

## Quality gate

The official command was run on the prepared release tree:

```powershell
.\.venv\Scripts\python.exe scripts/quality_gate.py
```

Result:

- **937 passed**
- branch coverage **94.49%**, threshold unchanged at 85%
- Ruff lint and format PASS
- mypy strict PASS
- `pip check` PASS
- **QUALITY GATE: PASS**

## Release handoff

The following commands are proposed and were **not executed**:

```powershell
Set-Location C:\icylens

git status --porcelain
git diff --check

git add README.md apps/api/.env.example apps/api/app/core/config.py apps/api/pyproject.toml apps/api/tests/conftest.py apps/api/tests/test_analysis_contracts.py apps/api/tests/test_config.py docs/API_CONTRACTS.md docs/ARCHITECTURE.md docs/RELEASE_V0_5_0.md
git commit -m "release: prepare v0.5.0 educational baseline"

git status --porcelain
git log --oneline -3
```

After the release commit is clean and verified, create the annotated tag from
that exact commit:

```powershell
git tag -a v0.5.0 -m "iCYLENS v0.5.0 - Phase 05 educational local release"
git rev-parse HEAD
git rev-parse v0.5.0^{}
git show --stat --oneline v0.5.0
```

Do not move any historical tag. If publication is authorized later:

```powershell
git push origin main
git push origin v0.5.0
```

## Release decision

**Release preparation: PASS.**

The working tree contains a coherent `0.5.0` candidate with matching package,
settings, health, OpenAPI, tests, and active documentation. The acceptance
record is versioned at `a98dd12`; the remaining release changes are ready to be
committed and tagged from the resulting release commit.

**Educational Local Readiness: READY WITH CONDITIONS.**

**Public Production Readiness: NOT READY.**

Phase 06 has not been started.
