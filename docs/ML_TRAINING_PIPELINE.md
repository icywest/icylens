# ML Training Pipeline

## Scope

Phase 03.03 adds reproducible offline supervised-training infrastructure over
verified Phase 03 dataset artifacts. It does not evaluate the sealed test set,
serve predictions, produce malware verdicts, download data, or claim scientific
representativeness. Feature schema `1.0.0` remains unchanged.

```text
verified dataset artifact
  -> integrity, schema, extraction, label, provenance, split, and size checks
  -> training records -> fit preprocessing + model
  -> validation records -> transform + exploratory metrics
  -> test records -> custody/class-presence check only; no feature matrix
  -> typed experiment report
  -> controlled joblib artifacts + SHA-256 descriptors
```

## Dataset eligibility

Training first repeats dataset integrity verification. The manifest must be
ready, use feature schema `1.0.0`, and contain only supported extraction version
`static-analysis-adapter/1.0.0`. All identities must be unique, every record
must have an assigned split, `unknown` labels are rejected, and both benign and
malicious must meet configurable minimums in training, validation, and sealed
test custody. The default maximum is 10,000 records.

Datasets containing only explicit synthetic provenance and synthetic labels run
as `synthetic_demo`. Synthetic and non-synthetic records cannot be mixed. A
non-synthetic eligible dataset runs as `research_evaluation`, but the report
still records `scientific_representativeness: not_established`; automation
cannot prove source quality, population coverage, absence of poisoning, or real
detection validity.

## Feature matrix and preprocessing

The matrix follows the 14-field `PREDICTIVE_FEATURE_ORDER` exactly. Five numeric
values are explicit floats, two categorical values remain strings until
encoding, and seven booleans become explicit 0/1 values. SHA-256, record ID,
filename, timestamps, label, split, provenance, and dataset identity never enter
the matrix.

Both categorical fields use `OneHotEncoder` with all contract categories listed
explicitly and `handle_unknown="ignore"`. This avoids invented ordinal meaning
and produces stable width. The final matrix contains 23 float columns:

- 5 numeric;
- 8 detected-format one-hot columns;
- 3 format-consistency one-hot columns; and
- 7 boolean columns.

Logistic Regression uses `StandardScaler` on numeric fields. Random Forest and
HistGradientBoosting use explicit float conversion without numeric scaling,
because tree split ordering does not benefit from standardization. Each
preprocessor and estimator is enclosed in one scikit-learn `Pipeline`.

Only training calls `fit`. Validation calls `predict`, which reuses the already
fitted transformer. No test feature matrix is constructed. The experiment
contract records `fit_partition: training` and `test_set_accessed: false`.

## Baseline configurations

| Model | Effective defaults | Numeric processing |
|---|---|---|
| Logistic Regression | `C=1.0`, `max_iter=300`, `solver=lbfgs`, `class_weight=None`, seed 42 | StandardScaler |
| Random Forest | 100 estimators, unlimited depth, leaf minimum 1, `class_weight=None`, `n_jobs=1`, seed 42 | Float passthrough |
| HistGradientBoosting | learning rate 0.1, 100 iterations, 31 leaf nodes, leaf minimum 5, seed 42 | Float passthrough |

These are moderate baselines, not tuned candidates. Random Forest is not given
preference. Configuration schemas cap iterations, estimators, depth, leaves,
parallelism, input records, transformed columns, and artifact size. One CLI
invocation runs exactly one experiment containing exactly three models.

## Validation metrics

Metrics are exploratory and use validation only: confusion matrix, malicious
precision/recall/F1, balanced accuracy, class support, prediction counts, and
an explicit list of undefined metrics. A zero division is numerically serialized
as zero only while its metric name is also recorded as undefined.

`synthetic_demo` results prove that code paths execute; they do not measure
malware detection. Tiny validation support cannot establish superiority,
uncertainty, calibration, robustness, or statistical significance. PR-AUC and
full evaluation are deferred until 03.04 and an adequate dataset.

## Reproducibility metadata

Experiment schema `1.0.0` records dataset ID/version/digest, feature and
extraction versions, training pipeline version, algorithm and hyperparameters,
seed, Python/NumPy/scikit-learn/joblib versions, preprocessing configuration,
training/validation counts and class distributions, timestamp, mode, metrics,
and test isolation. Equal input/configuration in the validated environment
produces equal predictions in automated tests.

Bit-for-bit results are not promised across operating systems, CPU libraries,
architectures, dependency versions, or future algorithm implementations.

## Experiment artifacts and serialization security

The recommended local output is:

```text
experiments/generated/<experiment-id>/
  experiment.json
  validation_metrics.json
  models/
    logistic_regression.joblib
    random_forest.joblib
    hist_gradient_boosting.joblib
```

Experiment IDs are safe bounded path components. Export writes into a staging
directory, enforces a default 100 MiB limit per model, computes model SHA-256
and size descriptors, refuses overwrite, and atomically renames the completed
directory. Failures clean staging. Generated experiments are ignored by Git.

Joblib uses pickle-compatible serialization and can execute code while loading.
This checkpoint deliberately implements no model-loading function. Verification
reads bytes to check typed metadata, size, safe relative paths, and SHA-256, but
never deserializes a model. Only artifacts created by this controlled local
pipeline may later be considered, after provenance and compatibility checks.
SHA-256 detects changes when its trusted descriptor is retained; it does not
authenticate a publisher or make untrusted pickle safe.

## CLI

From `apps/api`:

```powershell
.\.venv\Scripts\python.exe scripts\train_models.py `
  --dataset ..\..\datasets\generated\lesson-set\1.0.0 `
  --output ..\..\experiments\generated `
  --experiment-id lesson-baselines-001 `
  --seed 42
```

The CLI verifies the dataset, trains the three candidates, writes one new
experiment, prints validation metrics and interpretation mode, and returns
nonzero on failure. Reusing an experiment ID never overwrites its artifact.

## Future evaluation and inference

Phase 03.04 may compare validation behavior, evaluate the sealed test once under
an approved protocol, and add explainability. A later inference boundary must
reuse the complete fitted `Pipeline`, not independently recreate encoding or
scaling. Safe model admission/loading is reviewed again before serving.
