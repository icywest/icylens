# Phase 03 / Checkpoint 03.01 Acceptance

Status: **PASS**  
Date: 2026-10-25

## A. Initial audit

The repository was clean on `main`. No ML package, feature schema, dataset
contract, training pipeline, inference path, dataset directory, or ML endpoint
existed. Phase 02 exposed a typed `StaticAnalysisResponse` backed by one bounded
upload read and these reusable observations:

- actual file size in bytes: positive integer;
- whole-file Shannon entropy: finite float from 0 through 8 bits/byte;
- printable ASCII observed/retained counts: non-negative integers;
- explicit string truncation and indicator truncation booleans;
- leading-signature format: PDF, PNG, JPEG, GIF, ZIP, PE, ELF, or unknown;
- extension/signature consistency: match, mismatch, or unknown;
- bounded informational indicator IDs with source and optional offset/evidence;
- SHA-256 identity: 64 lowercase hexadecimal characters.

String extraction also records minimum length, maximum retained strings, and
maximum characters per string. Truncation means either a qualifying string
exceeded its preview bound or qualifying strings exceeded the retention bound.
Indicator truncation means the configured output cap omitted further results.

The unchanged pre-implementation gate passed: 208 tests, 99.08% total
coverage, Ruff lint/format, strict mypy, and `pip check`. The command printed in
the checkpoint request assumes a repository-root virtual environment, but this
repository keeps `.venv` and `scripts/quality_gate.py` under `apps/api`; the
equivalent gate was run from that directory without changing any check.

## B. Implementation

Created:

- `apps/api/app/ml/__init__.py`
- `apps/api/app/ml/datasets.py`
- `apps/api/app/ml/features.py`
- `apps/api/app/ml/validation.py`
- `apps/api/app/schemas/ml_dataset.py`
- `apps/api/app/schemas/ml_features.py`
- `apps/api/tests/fixtures/ml_dataset_v1.json`
- `apps/api/tests/test_ml_data_foundation.py`
- `docs/ML_DATASET_GOVERNANCE.md`
- `docs/ML_FEATURE_CONTRACT.md`
- `docs/PHASE_03_CHECKPOINT_03_01_ACCEPTANCE.md`

Modified:

- `README.md`
- `docs/ARCHITECTURE.md`
- `docs/DEVELOPMENT_LOG.md`

Deleted: none. No existing API contract, dependency, configuration threshold,
quality exclusion, or historical acceptance report was changed.

## C. Feature contract

Schema `1.0.0` defines the following exact predictive order:

1. `file_size_bytes` - integer, bytes, greater than zero.
2. `shannon_entropy` - finite float, bits/byte, 0 through 8.
3. `printable_string_count` - non-negative integer count.
4. `retained_string_count` - non-negative integer count.
5. `indicator_count` - non-negative integer count.
6. `detected_format` - supported format category.
7. `format_consistency` - match/mismatch/unknown category.
8. `has_url_candidate` - boolean.
9. `has_ipv4_candidate` - boolean.
10. `has_powershell_reference` - boolean.
11. `has_encoded_command_token` - boolean.
12. `has_script_reference` - boolean.
13. `strings_truncated` - boolean quality observation.
14. `indicators_truncated` - boolean quality observation.

`feature_schema_version` is required metadata but not in the predictive order.
Missing schema `1.0.0` fields, unexpected fields, non-finite values, invalid
types/ranges/categories, and incompatible versions are rejected rather than
imputed. SHA-256, record ID, filename, UUID, timestamps, label, source,
provenance, extraction configuration, and split are excluded from model input.

## D. Dataset governance

Each record separates identity, features, label, provenance, extraction
settings, and split. `unknown` ground truth is never treated as benign and is
ineligible for supervised training. Synthetic labels are explicit. Verified
benign/malicious labels also require supported provenance and a verification
date for eligibility; static indicators never manufacture ground truth.

Imports remain `unassigned` until a reviewed split operation. Exact SHA-256
duplicates, conflicting labels, duplicate record IDs, and cross-split copies
are errors. Repeated synthetic feature templates are warnings. Hash equality
does not solve near-duplicate or family leakage, so future real data needs
grouped/temporal evaluation, source diversity review, contamination analysis,
and an untouched independent test set. Licensing, privacy, reproducibility,
class imbalance, and safe malicious-sample controls are specified in the
governance policy.

## E. Validation demonstration

The deterministic three-record fixture validates successfully, retains
`unassigned` splits, has explicit synthetic provenance, and includes an
`unknown` label that produces the expected supervised-training exclusion
warning. Focused tests also construct controlled failures and verify these
issue codes:

| Scenario | Result |
|---|---|
| Valid typed static report extraction | valid feature vector `1.0.0` |
| Same SHA-256 twice | `duplicate_sha256` error |
| Same SHA-256 with benign/malicious labels | `conflicting_labels` error |
| Same SHA-256 in training and test | `cross_split_duplicate` error |
| Missing entropy plus extra lifecycle field | invalid record (`missing`, `extra_forbidden`) |
| Unknown provenance | `unsupported_provenance` error |
| Unknown ground-truth label | `unknown_label_excluded` warning; not eligible |
| Different hashes with identical synthetic vector | `repeated_synthetic_template` warning |

No validator repairs or relabels a record.

## F. Quality results

Post-implementation unified Quality Gate:

- pytest: **230 passed**;
- coverage: **98.87%** total statement/branch coverage (85% floor unchanged);
- Ruff lint: **PASS**;
- Ruff format: **PASS** (51 files checked);
- mypy strict: **PASS** (41 source files checked);
- `pip check`: **PASS**, no broken requirements;
- overall Quality Gate: **PASS**.

## G. Explicación de arquitectura ML

La ingeniería de características transforma observaciones reproducibles en
variables con nombres, tipos, unidades y orden estables para un modelo. Una
característica describe la muestra; una etiqueta representa la verdad objetivo
que el modelo intentará aprender. Mezclarlas produciría una evaluación falsa.

La procedencia importa porque permite conocer quién obtuvo el dato, con qué
permiso, cuándo, bajo qué licencia, cómo verificó la etiqueta y con qué versión
se extrajeron las características. Sin esa evidencia no se puede reproducir ni
auditar un resultado.

La fuga de datos ocurre cuando el entrenamiento recibe información que no
estaría disponible en una predicción real o cuando muestras relacionadas
aparecen en entrenamiento y evaluación. Por eso la etiqueta, su fuente, el
dataset, el split, los UUID y las fechas no son características, y el conjunto
de prueba queda sellado durante la selección del modelo.

SHA-256 identifica bytes exactos y permite deduplicarlos, pero no expresa una
propiedad generalizable del contenido; usarlo como número predictivo fomentaría
memorización. Tampoco detecta variantes cercanas o familias relacionadas.

Un indicador sospechoso solo registra una observación textual. Puede aparecer
en documentación o archivos benignos; la entropía alta también tiene causas
legítimas. Convertirlos automáticamente en `malicious` haría que el modelo
aprendiera la misma regla que generó la etiqueta y no una verdad independiente.

En un checkpoint posterior, Random Forest recibirá una matriz construida en el
orden contractual, con categorías codificadas mediante un preprocesamiento
ajustado únicamente al conjunto de entrenamiento. Antes harán falta datos
reales autorizados, etiquetas verificadas, splits agrupados, un conjunto de
prueba independiente y métricas honestas. Este checkpoint no entrena ni mide
ningún modelo.

## H. Final checkpoint

**PASS** - the implementation, focused demonstrations, regression suite, type
checks, formatting/lint checks, dependency integrity, and full gate all pass.
No detection-performance claim is made.

## I. Version-control handoff

No add, commit, tag, or push was executed. There were no unrelated pre-existing
changes. Suggested Conventional Commit grouping:

- `feat(ml): add versioned feature and dataset contracts`
- `test(ml): validate extraction governance and leakage controls`
- `docs(ml): document dataset governance and checkpoint acceptance`

## J. Next step

**Phase 03 / Checkpoint 03.02 - Dataset Builder & Validation Pipeline.**

It is not implemented by this checkpoint.
