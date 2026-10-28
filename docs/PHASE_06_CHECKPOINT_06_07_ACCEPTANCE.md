# Phase 06 Checkpoint 06.07 Acceptance

Date: 2026-10-27

Scope: synthetic investigation scenarios, deterministic case studies and
educational demonstration foundation

Decision: **PASS**

## Initial audit

- Branch `main`; initial `HEAD` and `origin/main` were both
  `713d06f1509b06b755c172a8e42907431d73eeca`.
- Initial working tree was clean and all four 06.06 commits (`e5db21c`,
  `f201e77`, `9ef75bc`, `713d06f`) were integrated.
- Metadata remained `0.5.0`; annotated `v0.5.0` was intact and unmoved.
- Baseline was 1,165 tests, 94.86% coverage, 35 HTTP operations, with Ruff,
  strict mypy and `pip check` passing.
- `POST /api/v1/multilayer/analyze` and `GET
  /api/v1/multilayer/schema` retained their 06.06 contracts.
- P05-CONC-008 remained documented and unchanged.

## Accepted design

Strict frozen contracts separate metadata, fixture source declarations,
assertion selections, expectations, observed outcomes, validation and compact
educational reports. An immutable registry exposes 11 bounded scenarios. The
generator creates only structurally valid backend educational evidence with
fixed inputs and canonical IDs.

Execution passes the generated batch through the existing identity,
correlation, sufficiency and decision-trace services. Expectations are read
only after computation and cannot create a relationship, identity, assessment
or trace. Deliberately altered expectations produce `failed` validation while
the actual engine result remains unchanged.

The positive cases are exact SHA-256, CVE, source-scoped analysis identity and
validated explicit-reference relationships already supported by Phase 06.
Negative cases retain conflicts, missing identity/relationship gaps,
not-applicable domains, unsupported assertions, namespace separation,
categorical uncertainty and valid empty graphs.

No HTTP route was added. This retains 35 operations and keeps the 06.06
client-declared admission boundary independent from backend-generated fixture
provenance. No analytical rule, assertion policy, trust rule, score, verdict,
persistence or external effect was introduced.

## Verification

`tests/test_synthetic_investigation_scenarios.py` adds 61 focused cases,
including parameterized execution and determinism checks for every registry
entry. Coverage includes discovery, unknown IDs/versions, duplicate IDs,
immutability, strict definitions, all required scenario families, mismatched
expectations, no silent correction, provenance, cross-namespace separation,
reference closure, stable IDs/traces, ordering invariance, resource/output
limits, privacy canaries, absence of filesystem/network/subprocess/model work,
client trust-escalation rejection and OpenAPI compatibility.

## Quality gate

The final mandatory gate completed with Ruff lint/format, strict mypy, pytest,
coverage and `pip check` passing. `git diff --check` also passed. Exact final
counts are recorded in `docs/DEVELOPMENT_LOG.md` and the checkpoint handoff.

## Git handoff

Suggested Conventional Commits:

1. `feat(scenarios): add strict synthetic scenario contracts`
2. `feat(scenarios): add deterministic registry generation and execution`
3. `test(scenarios): cover deterministic educational boundaries`
4. `docs(phase-06): document checkpoint 06.07 acceptance`

No branch, commit, tag or push is performed automatically. Checkpoint 06.08 is
not started.
