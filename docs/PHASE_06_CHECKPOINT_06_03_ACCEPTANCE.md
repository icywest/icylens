# Phase 06 Checkpoint 06.03 Acceptance

Date: 2026-10-27

Scope: Deterministic multilayer evidence correlation

Decision: **PASS**

## Initial audit

- Branch `main`; initial `HEAD` and `origin/main` were both
  `d94e623b9cdf7f39eebd3bc631f6e1188ab84c59`.
- Initial working tree: clean.
- All four 06.02 commits are integrated: `386b870`, `06a4d3c`, `4bec961`,
  `d94e623`.
- Metadata is `0.5.0`; annotated `v0.5.0` remains at Phase 05 release commit
  `747b273` and was not moved.
- Accepted 06.02 baseline: 985 tests, 94.59% coverage, Ruff, strict mypy,
  `pip check`, `git diff --check` and unified quality gate PASS.
- P05-CONC-008 remains inherited and unchanged.

## Compatibility and implementation

The engine accepts a validated 06.01 `EvidenceBatch` and recomputes 06.02
identity resolution. Candidate selection consumes its groups, diagnostic
matches and conflicts without duplicating identity extraction, equality,
grouping or conflict detection. No precalculated result can diverge from the
batch.

Strict frozen contracts cover rules, requirements, candidates, evidence
references, evaluations, conflicts, relationships, graph nodes/edges, summary
and result. Six immutable rules support four narrow relationship types and
retain negative outcomes. Selection uses groups and explicit references, never
all record pairs. Compatible context is non-positive/non-transitive; conflicts
suppress relationships; provenance and trust remain per record.

There is no endpoint, persistence, I/O, dynamic execution, ML/LLM inference,
score, verdict, causal/temporal inference, trust promotion, automatic action or
06.04 work.

## Verification

`tests/test_multilayer_correlation.py` contains 49 focused cases covering all
supported families, exact/missing/conflicting/unsupported evidence, context
non-edges, duplicates, the negative matrix, linear graph projection,
deterministic permutations, provenance/trust, registry immutability, strict
versions/IDs, dangling/circular/mismatched references, privacy, limits, round
trips and absence of I/O.

## Final quality gate

The mandatory `scripts/quality_gate.py` completed with `QUALITY GATE: PASS`:

- pytest: **1,034 passed** in 267.12 seconds (49 added);
- statement/branch coverage: **94.81%**, above both the unchanged 85% gate and
  the 06.02 baseline of 94.59%;
- Ruff lint: PASS;
- Ruff format: PASS, 177 files;
- strict mypy: PASS, 147 source files;
- `pip check`: PASS.

The focused 06.03 suite passed 49 tests with 99% coverage over the new schema
and correlation package. No threshold, test or quality check was removed or
weakened. `git diff --check` is part of the final repository review.

## Git handoff

Suggested Conventional Commits:

1. `feat(correlation): add strict multilayer correlation contracts`
2. `feat(correlation): add deterministic rule engine and evidence graph`
3. `test(correlation): cover supported and negative correlation semantics`
4. `docs(phase-06): document checkpoint 06.03 acceptance`

No commit, tag or push is performed automatically.
