# Phase 03 / Checkpoint 03.03 Acceptance

Status: **PASS**  
Date: 2026-10-25

## A. Initial audit

The repository was clean on `main`. Phase 03.02 provided verified versioned
dataset artifacts, strict eligibility, deterministic splits, and canonical
integrity. The effective feature order remained five numeric, two categorical,
and seven boolean fields. Test was sealed and synthetic labels explicit.

The unchanged baseline passed with 284 tests and 96.42% total coverage. Ruff,
strict mypy, `pip check`, and the unified gate passed. NumPy, scikit-learn, and
joblib were initially absent. Official CPython 3.13 wheels were verified and
the editable environment resolved NumPy 2.5.4, scikit-learn 1.9.1, joblib 1.6.0,
and SciPy 1.18.1.

## B. Implementation

The checkpoint adds deterministic matrix/preprocessing construction, three
bounded baseline Pipelines, repeated dataset admission checks, exploratory
validation metrics, typed experiment reporting, controlled local joblib export,
byte-level artifact verification without deserialization, and a safe CLI.

## C. Training architecture

```text
verified dataset artifact
  -> manifest/digest/schema/extraction/provenance/split/resource checks
  -> training -> fit(ColumnTransformer + estimator)
  -> validation -> transform/predict/exploratory metrics
  -> test -> class/split custody check only; no matrix or predictions
  -> typed report
  -> staged model artifacts + SHA-256/size descriptors
```

## D. Effective model configuration

| Candidate | Effective defaults | Preprocessing |
|---|---|---|
| Logistic Regression | `C=1.0`, `max_iter=300`, `lbfgs`, no class weight, seed 42 | Numeric StandardScaler + one-hot + boolean float |
| Random Forest | 100 trees, no depth cap, leaf minimum 1, `n_jobs=1`, no class weight, seed 42 | Numeric float passthrough + one-hot + boolean float |
| HistGradientBoosting | learning rate 0.1, 100 iterations, 31 leaf nodes, leaf minimum 5, seed 42 | Numeric float passthrough + one-hot + boolean float |

No candidate receives tuning or privileged test information.

## E. Preprocessing

The exact 14-feature order becomes 23 float columns: five numeric, eleven
explicit categorical one-hot columns, and seven boolean 0/1 columns. Explicit
categories prevent ordinal meaning and stabilize width. `handle_unknown` maps a
future unseen category to the all-zero block. Each transformer is enclosed with
its model in one Pipeline. Tests inspect Logistic scaler means and confirm they
equal training-only means. Instrumentation confirms matrices are built only for
training and validation.

## F. Dataset integrity and eligibility

Admission repeats canonical digest and derived metadata verification, requires
feature schema `1.0.0`, supported extraction versions, unique hashes, assigned
splits, no `unknown` labels, bounded record counts, and both classes in training,
validation, and test custody. Mixed synthetic/real evidence is rejected.

All-synthetic records produce `synthetic_demo`. Non-synthetic eligible records
produce `research_evaluation`, but both retain
`scientific_representativeness: not_established` unless external evidence is
provided in a future research process.

## G. Synthetic demonstration

A safe deterministic dataset of 40 metadata-only records produced 28 training,
6 validation, and 6 sealed test records. All three default models trained,
experiment export verified, and repeated training produced identical validation
predictions for every candidate.

The six-record synthetic validation split yielded the following smoke-test
metrics for each model: confusion matrix `[[3, 0], [0, 3]]`, precision 1.0,
recall 1.0, F1 1.0, and balanced accuracy 1.0. These values are **not evidence
of malware-detection performance**: the dataset is tiny, synthetic, and not
scientifically representative. They must not be used to rank the candidates.

Default serialized model evidence from that run:

| Model | Bytes | SHA-256 |
|---|---:|---|
| HistGradientBoosting | 5,381 | `6587496a987ec5553901784080ab536c9313bd589a58622787990314c6413417` |
| Logistic Regression | 1,848 | `226953fe88353779fc4147c484f03e7e331b6cef06fa351b85d2bef47dd952ed` |
| Random Forest | 17,824 | `a7178080dbca5c96d3e90d79cd092413f59287794407b4a2d9241f54e5755614` |

The temporary demonstration directory was removed after verification.

## H. Reproducibility

The report records dataset ID/version/digest, schemas, extraction versions,
algorithm/hyperparameters, seed, runtime dependency versions, preprocessing,
class distributions, counts, timestamp, and interpretation mode. With the same
dataset, configuration, seed, and installed environment, all three repeated
prediction arrays matched.

Bitwise equality is not promised across operating systems, CPU libraries,
architectures, dependency versions, or later estimator implementations.

## I. Quality results

- Previous tests: **284**.
- New focused tests: **31**.
- Total: **315 passed**.
- Total statement/branch coverage: **95.07%**.
- Ruff lint: **PASS**.
- Ruff format: **PASS**, 65 files checked.
- Mypy strict: **PASS**, 53 source files checked.
- `pip check`: **PASS**.
- Unified Quality Gate: **PASS**.

No threshold or exclusion was weakened.

## J. Security assessment

Controls include dataset integrity revalidation, typed/bounded configuration,
record and transformed-column caps, bounded estimators/iterations, `n_jobs=1`,
model-size limits, safe experiment IDs, non-overwrite, staging cleanup, local
I/O only, no sample bytes, and no test prediction.

Joblib artifacts are pickle-compatible and unsafe from untrusted sources. No
model-loading API exists. Verification hashes bytes without deserializing them.
SHA-256 is integrity evidence under a trusted descriptor, not authenticity.
Residual risks include plausible label poisoning, compromised source metadata,
near-duplicate/family leakage, dependency/platform drift, and local artifact
confidentiality. No Critical/High issue remains in the scoped local workflow.

## K. Explicación de arquitectura ML

El aprendizaje supervisado ajusta parámetros para relacionar features con
labels conocidas. Se usan tres algoritmos porque representan sesgos inductivos
distintos: Logistic Regression es una frontera lineal; Random Forest combina
árboles independientes para relaciones no lineales; Gradient Boosting construye
árboles secuenciales que corrigen errores anteriores.

`ColumnTransformer` aplica transformaciones diferentes a columnas numéricas,
categóricas y booleanas. Solo se ajusta en training porque calcular escalas o
categorías con validation/test transmitiría información futura y produciría
data leakage. El Pipeline conserva exactamente el mismo preprocessing para una
inferencia posterior.

La demostración sintética prueba integración, determinismo, serialización y
aislamiento, no eficacia real. Phase 03.04 deberá definir el protocolo de
evaluación, abrir test bajo control, analizar incertidumbre/limitaciones y añadir
explicabilidad sin reutilizar test para tuning.

## L. Decision

**PASS** - the three candidates train through one interface; dataset admission,
training-only preprocessing, validation metrics, test sealing, reproducibility,
controlled persistence, regression tests, and all quality gates are verified.

## M. Version-control handoff

Created:

- `apps/api/app/ml/experiments.py`
- `apps/api/app/ml/models.py`
- `apps/api/app/ml/preprocessing.py`
- `apps/api/app/ml/training.py`
- `apps/api/app/schemas/ml_experiment.py`
- `apps/api/scripts/train_models.py`
- `apps/api/tests/test_ml_training_pipeline.py`
- `docs/ML_TRAINING_PIPELINE.md`
- `docs/PHASE_03_CHECKPOINT_03_03_ACCEPTANCE.md`

Modified:

- `.gitignore`
- `README.md`
- `apps/api/app/ml/__init__.py`
- `apps/api/pyproject.toml`
- `docs/ARCHITECTURE.md`
- `docs/DEVELOPMENT_LOG.md`
- `docs/ML_DATASET_GOVERNANCE.md`
- `docs/ML_FEATURE_CONTRACT.md`

Deleted: none. Unrelated changes: none. No add, commit, tag, or push was run.

Suggested commits:

- `feat(ml): add reproducible baseline training pipelines`
- `test(ml): verify preprocessing isolation and experiment security`
- `docs(ml): document training workflow and checkpoint acceptance`

## N. Next step

**Phase 03 / Checkpoint 03.04 - Model Evaluation, Validation & Explainability.**

It was not implemented automatically.
