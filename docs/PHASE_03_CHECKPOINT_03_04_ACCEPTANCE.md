# Phase 03 / Checkpoint 03.04 Acceptance

Status: **PASS**  
Date: 2026-10-25

## A. Initial audit

The repository was clean on `main`. The reported baseline was reproduced: 315
tests, 95.07% total coverage, Ruff lint/format, strict mypy, `pip check`, and the
unified Quality Gate passed. Phase 03.03 correctly fit preprocessing on training,
predicted validation, emitted malicious-positive summary metrics, retained
trusted Pipelines in process, exported pickle-compatible joblib without loading
it, and constructed no test feature matrix.

The gaps were full per-class/imbalance/probability/error metrics, explicit
unavailable values, threshold analysis, explainability, common-basis comparison,
selection abstention, and separate safe evaluation artifacts.

## B. Changes applied

Created:

- `apps/api/app/ml/evaluation.py`
- `apps/api/app/ml/evaluation_artifacts.py`
- `apps/api/app/schemas/ml_evaluation.py`
- `apps/api/scripts/evaluate_models.py`
- `apps/api/tests/test_ml_model_evaluation.py`
- `docs/ML_MODEL_EVALUATION.md`
- `docs/PHASE_03_CHECKPOINT_03_04_ACCEPTANCE.md`

Modified:

- `.gitignore`
- `README.md`
- `docs/ARCHITECTURE.md`
- `docs/DEVELOPMENT_LOG.md`
- `docs/ML_DATASET_GOVERNANCE.md`
- `docs/ML_TRAINING_PIPELINE.md`

Deleted: none. Unrelated changes: none.

## C. Evaluation architecture

```text
verified dataset + trusted in-process TrainedExperiment
  -> experiment/dataset/schema/digest/model-set checks
  -> validation records -> original 14-feature matrix
  -> fitted Pipeline predict + malicious predict_proba
  -> metrics + thresholds + aggregate errors
  -> seeded permutation importance on original features
  -> deterministic comparison -> selection or abstention
  -> staged canonical JSON report + SHA-256 manifest
```

The service does not duplicate fitting, start FastAPI, deserialize joblib, or
construct a test feature matrix.

## D. Metric verification

Independent known cases verify the fixed `(benign, malicious)` order. Perfect
labels produce `[[2, 0], [0, 2]]`, macro F1 1.0 and balanced accuracy 1.0.
All-negative and all-positive predictions verify false-negative and
false-positive counts. A mixed case verifies one FP and one FN. Missing
denominators and single-class validation produce explicit unavailable objects.

For actual `[0, 0, 1, 1]` and malicious probabilities
`[0.1, 0.4, 0.35, 0.8]`, tests verify ROC-AUC 0.75, average precision 5/6,
Brier score 0.158125, and log loss approximately 0.4722879538. Invalid shapes,
NaN, infinity, and out-of-range probabilities are rejected. The malicious
column is located through fitted class labels rather than assumed by position.

## E. Explainability

Permutation importance runs through each complete Pipeline on the 14 original
validation columns using macro F1, seed 42, `n_jobs=1`, and bounded repeats.
This preserves source feature names and permutes a categorical source as a
whole before one-hot encoding. Tests verify determinism, repeat limits, and the
stable 14-feature order.

Importance is model/dataset-specific, not causal or a local contribution.
Correlated features can divide or mask importance. No SHAP or fabricated local
narrative was added.

## F. Comparison and selection

All candidates share the dataset digest, validation partition, label order,
feature contract, and definitions. Comparison is algorithm-sorted and covers
macro F1, malicious recall, FPR, balanced accuracy, average precision, and
support.

The policy declares macro F1 primary, a 0.02 minimum margin, a malicious recall
floor of 0.5, and an operational 100-record support gate. The gate is not a
scientific sample-size claim. It handles missing metrics, low support, small
margins/ties, validation failure, and selection. Synthetic mode always returns
`insufficient_evidence`; no candidate was selected.

## G. Synthetic demonstration

A metadata-only deterministic demonstration used 40 explicitly synthetic
records: 28 training, 6 validation, and 6 sealed test. Dataset digest was
`8757c02acedcd2d8938e20e5a07f4135aab33bb998eb31a5a4617fa142ab96ad`.

All three default models produced validation confusion counts TN=3, FP=0,
FN=0, TP=3; macro F1, malicious recall, balanced accuracy, and average precision
were 1.0. These are **synthetic smoke-test values only**, not real detection
performance or ranking evidence. Selection correctly abstained with reason
`synthetic_evidence`.

With five repeats, all three reported `file_size_bytes` as the largest observed
permutation value (mean 0.4, standard deviation about 0.2494). This reflects the
constructed toy generator and must not be interpreted causally or generalized.

Repeated evaluation produced identical model reports and comparison. The
temporary 20,292-byte canonical report verified against SHA-256
`3c3c3bd494c6702bf9fb58c97e1d95bacc9a1f0468cdc90051d05c645f17f3be`;
its temporary directory was removed.

## H. Test isolation

Instrumentation observed exactly one matrix construction containing only the
`validation` split. The same matrix feeds predictions, probability metrics,
threshold analysis, and permutation importance. No test transformation,
prediction, importance, threshold, metric, distribution-derived tuning, or
selection occurred. Reports retain `test_set_accessed: false`.

A future one-time protocol was written before opening test: freeze dataset,
candidate, Pipeline, threshold, metrics, subgroup plan and acceptance rules;
approve the immutable plan; evaluate once; publish all predefined results; and
prohibit post-test tuning. Test remains sealed in this checkpoint.

## I. Quality results

- Previous tests: **315**.
- New focused tests: **37**.
- Total: **352 passed**.
- Total statement/branch coverage: **94.11%**.
- Ruff lint: **PASS**.
- Ruff format: **PASS**, 70 files checked.
- Mypy strict: **PASS**, 57 source files checked.
- `pip check`: **PASS**.
- Unified Quality Gate: **PASS**.

The 85% floor and exclusions were unchanged.

## J. Security assessment

Evaluation uses trusted in-process Pipelines and contains no `joblib.load`.
Joblib remains pickle-compatible and unsafe for arbitrary external artifacts;
SHA-256 integrity does not establish publisher authenticity. Reports are
aggregate-only and exclude hashes, IDs, filenames, strings, secrets, personal
data, and sample bytes.

Controls cap validation records, candidates, permutation repeats, thresholds,
parallelism, and JSON size. IDs are safe path components; export is staged,
non-overwriting, atomic, digest-verified, and cleaned on failure. No network,
cloud, binary execution, or dynamic import occurs. No open Critical/High issue
remains in the scoped local workflow.

## K. Technical explanation

1. Accuracy can hide complete failure on a minority class, so class metrics,
   balanced accuracy, and the majority baseline are reported.
2. Precision asks how many malicious predictions were correct; recall asks how
   many actual malicious observations were found.
3. A false positive flags benign as malicious; a false negative misses
   malicious. Their operational costs require context and are not universal.
4. Calibration matters because a probability such as 0.8 is meaningful only
   if comparable predictions occur at approximately that frequency; it is not
   established here.
5. Permutation importance measures validation-score degradation after
   disrupting one original feature.
6. Importance is not causality: correlation, sampling, and the fitted model can
   redistribute or hide influence.
7. Abstention is correct when evidence is synthetic, small, tied, marginal, or
   incomplete; choosing anyway would create false certainty.
8. Typed labels, probability semantics, thresholds, preprocessing identity and
   limitations prepare contracts an inference lifecycle can later enforce.
9. Test must remain untouched so it can provide one independent final estimate
   after all choices are frozen.

## L. Final decision

**PASS.** Metrics, probability edge cases, original-feature permutation
importance, privacy-conscious errors, reproducible comparison, conservative
abstention, safe artifacts, test isolation, and every Quality Gate are verified.
A ranking result is neither required nor supported by current evidence.

## M. Version-control handoff

No `git add`, commit, tag, or push was run. Suggested commits:

- `feat(ml): add validation-only model evaluation and comparison`
- `test(ml): verify metrics explainability and test isolation`
- `docs(ml): document evaluation policy and checkpoint acceptance`

## N. Next step

**Phase 03 / Checkpoint 03.05 - ML Inference API & Model Lifecycle.**

It was not implemented automatically.
