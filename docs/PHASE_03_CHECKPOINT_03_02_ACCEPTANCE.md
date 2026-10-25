# Phase 03 / Checkpoint 03.02 Acceptance

Status: **PASS**  
Date: 2026-10-25

## A. Initial audit

The repository was clean on `main`. Phase 03.01 supplied strict feature and
record schemas, identity/label/provenance separation, structured validation,
exact duplicate/conflict detection, training eligibility, and a loadable
three-record JSON fixture. It had no bounded importer, build orchestration,
split planner, manifest, artifact writer/verifier, or dataset CLI.

The unchanged baseline passed with 230 tests and 98.87% total coverage. Ruff
lint/format, strict mypy, `pip check`, and the unified gate passed. FastAPI
started through `TestClient`; `/api/v1/health/` returned HTTP 200.

## B. Implementation

The pipeline adds bounded JSON/JSONL import, strict staged assessment,
deterministic deduplication, eligibility filtering, constrained label-stratified
splitting, typed manifests, canonical SHA-256 integrity, atomic non-overwriting
artifact export, verification, and a local argparse CLI. Feature schema `1.0.0`
and existing FastAPI contracts were not replaced.

## C. Pipeline architecture

```text
bounded local JSON/JSONL
  -> strict record schema
  -> provenance and label eligibility
  -> deterministic exact-hash canonicalization/conflict gate
  -> machine-readable validation report
  -> sha256-stratified-v1 split plan
  -> canonical digest + typed manifest
  -> staged records.jsonl / manifest.json / validation_report.json
  -> atomic rename and later integrity verification
```

Validation and splitting are independent from writing. Fatal findings or
infeasible splits produce no release artifact.

## D. Dataset builder

JSON accepts a top-level array; JSONL accepts one object per nonblank line.
Both require strict UTF-8 and Pydantic records. Defaults are 10 MiB input,
10,000 records, and 1 MiB per JSONL line. Reads are bounded; pickle, executable
payloads, network downloads, CSV, and Parquet are absent.

Exact duplicate groups preserve an existing assignment and then use the
lexically smallest record ID as the stable representative. Exclusions remain
in the report. Conflicting labels, label metadata, provenance, features,
extraction settings, record identities, or assigned splits are fatal. Unknown
labels are never relabeled and cannot enter supervised splits.

## E. Splitting

The default typed proposal is 70/15/15, seed 42, stratification by label,
minimum one record per class per split, and `sha256_exact_only` grouping.
Targets use stable largest remainders; records are ranked by SHA-256 of
`seed:sample_sha256`, not Python's randomized hash. Input permutation does not
change assignments.

Existing assignments are respected. Impossible minimums, tiny datasets,
single-class datasets, unknown labels, and duplicate hashes are rejected. No
family/campaign grouping field exists, so the planner makes no near-duplicate
or family-isolation claim. The test split is reserved for final future
evaluation and cannot be used for fitting or model selection.

## F. Representative manifest

The actual six-record deterministic demonstration produced:

```json
{
  "manifest_schema_version": "1.0.0",
  "dataset_id": "checkpoint-demo",
  "dataset_version": "1.0.0",
  "feature_schema_version": "1.0.0",
  "builder_version": "dataset-builder/1.0.0",
  "extraction_versions": ["static-analysis-adapter/1.0.0"],
  "record_count": 6,
  "eligible_record_count": 6,
  "excluded_record_count": 0,
  "label_counts": {"benign": 3, "malicious": 3},
  "split_counts": {"training": 2, "validation": 2, "test": 2},
  "source_identifiers": ["authorized-local-source"],
  "validation_summary": {
    "input_count": 6,
    "structurally_valid_count": 6,
    "governance_eligible_count": 6,
    "training_eligible_count": 6,
    "accepted_count": 6,
    "excluded_count": 0,
    "warning_count": 0,
    "error_count": 0,
    "issue_code_counts": {},
    "ready_for_training": true
  },
  "split_configuration": {
    "algorithm_version": "sha256-stratified-v1",
    "random_seed": 42,
    "training_fraction": 0.7,
    "validation_fraction": 0.15,
    "test_fraction": 0.15,
    "stratification": "label",
    "grouping_policy": "sha256_exact_only",
    "minimum_per_class_per_split": 1,
    "feature_schema_version": "1.0.0",
    "respect_existing_assignments": true
  },
  "integrity_algorithm": "sha256-canonical-json-v1",
  "content_integrity_digest": "cb69e0657247f9553849f13f90bd39bea8fbc0bba27ad8b2af9bc8da8412b9ac",
  "created_at": "2026-10-25T18:00:00Z",
  "created_by": "icylens-local-dataset-builder"
}
```

The digest covers canonicalization ID, dataset ID/version, builder/feature
versions, complete split configuration, and released records sorted by SHA-256.
It excludes itself and creation time. Loader verification also derives counts,
labels, splits, sources, extraction versions, feature versions, and validation
summary consistency.

## G. Demonstration evidence

- Successful build: 6 accepted records; splits 2/2/2; integrity `true`.
- Reversed input: identical assignments and identical digest.
- Exact duplicate: one stable representative and `exact_duplicate` exclusion.
- Conflicting hash: `conflicting_labels` and `cross_split_duplicate` errors.
- Tiny two-per-class dataset: `infeasible_stratification`; no artifact.
- Modified record: `integrity_mismatch`.
- Modified manifest count: `invalid_manifest`.
- Modified validation summary: `validation_summary_mismatch`.
- Existing artifact version: `artifact_exists`; no overwrite.
- Synthetic write failure: staging directory removed.
- Unsafe dataset ID: strict validation; no path escape.

## H. Quality results

- Previous tests: **230**.
- New focused tests: **54**.
- Total tests: **284 passed**.
- Total statement/branch coverage: **96.42%**.
- Ruff lint: **PASS**.
- Ruff format: **PASS**, 58 files checked.
- Mypy strict: **PASS**, 47 source files checked.
- `pip check`: **PASS**, no broken requirements.
- Unified Quality Gate: **PASS**.

No thresholds or exclusions were weakened.

## I. Security assessment

Controls include bounded reads, strict UTF-8/JSON, record/line caps, forbidden
unknown fields, safe path components, deterministic conflict handling,
non-overwrite, staging cleanup, local-only I/O, no executable deserialization,
no sample binaries, concise CLI errors, and artifact consistency/digest checks.

Residual risks: schema validation cannot detect plausible poisoned labels,
prove provenance/license assertions, discover family/near-duplicate leakage, or
protect against an attacker who can replace both artifact and digest. Local
filesystem permissions must protect potentially confidential provenance.

There are no unresolved Critical/High findings for the scoped local educational
pipeline.

## J. Explicación de arquitectura

Un dataset builder recibe registros estructurados, valida sus contratos,
documenta exclusiones, resuelve duplicados bajo reglas deterministas, planifica
splits y publica artefactos verificables. Un registro puede ser estructuralmente
válido pero no elegible para training por etiqueta desconocida, procedencia no
aceptable o ground truth sin verificar.

Deduplicar evita contar los mismos bytes varias veces y evita que una copia
exacta aparezca en entrenamiento y prueba. Sin embargo, un split aleatorio por
registro puede filtrar variantes de una misma familia, campaña o plantilla;
SHA-256 solo agrupa copias exactas.

El test sellado es necesario para medir el modelo una vez, después de tomar las
decisiones con training y validation. Si participa en tuning, deja de ser una
evaluación independiente.

El manifest fija identidad/versiones, configuración, conteos y digest, haciendo
reproducible y auditable la entrada. En 03.03 el trainer deberá verificar el
artefacto, ajustar transformaciones y modelos solo con `training`, comparar con
`validation` y reservar `test` para el resultado final. Construir correctamente
el dataset no demuestra que detecte malware real.

## K. Final checkpoint

**PASS** - all acceptance requirements are implemented and supported by the
demonstration, regression suite, security tests, typing, formatting, dependency
integrity, and unified gate.

## L. Version-control handoff

Created:

- `apps/api/app/ml/artifacts.py`
- `apps/api/app/ml/builder.py`
- `apps/api/app/ml/importing.py`
- `apps/api/app/ml/splitting.py`
- `apps/api/app/schemas/ml_manifest.py`
- `apps/api/scripts/dataset_cli.py`
- `apps/api/tests/test_ml_dataset_pipeline.py`
- `docs/ML_DATASET_PIPELINE.md`
- `docs/PHASE_03_CHECKPOINT_03_02_ACCEPTANCE.md`

Modified:

- `.gitignore`
- `README.md`
- `docs/ARCHITECTURE.md`
- `docs/DEVELOPMENT_LOG.md`
- `docs/ML_DATASET_GOVERNANCE.md`
- `docs/ML_FEATURE_CONTRACT.md`

Deleted: none. Unrelated changes: none. No add, commit, tag, or push was run.

Suggested commits:

- `feat(ml): add reproducible dataset builder and split planner`
- `test(ml): cover dataset import integrity and leakage controls`
- `docs(ml): document dataset pipeline and checkpoint acceptance`

## M. Next step

**Phase 03 / Checkpoint 03.03 - ML Training Pipeline & Baseline Model Comparison.**

It was not implemented automatically.
