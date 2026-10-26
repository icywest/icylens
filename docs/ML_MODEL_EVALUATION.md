# ML Model Evaluation

Phase 03.04 evaluates the three already-fitted baseline Pipelines in the same
trusted local process. It does not load joblib, tune candidates, select a
deployment threshold, open test, or expose an HTTP inference route.

## Validation-only flow

```text
verified dataset + in-process TrainedExperiment
  -> experiment/dataset/schema/digest compatibility
  -> validation records only -> 14-column original feature matrix
  -> each fitted Pipeline -> class prediction + malicious probability
  -> classification/probability/threshold/error reports
  -> permutation importance through the complete Pipeline
  -> same-partition comparison -> conservative selection or abstention
  -> typed, staged, non-overwriting evaluation artifact
```

Dataset verification can check the canonical release as a whole, but evaluation
constructs a feature matrix only for records whose split is `validation`.
Training distributions come from the immutable experiment report. Test features
and labels are not transformed, predicted, scored, used for importance, or used
for threshold/model selection. Reports assert `test_set_accessed: false`.

## Metric contract

Evaluation schema `1.0.0` fixes the order `(benign, malicious)`. `malicious` is
the positive class and `benign` the negative class:

- false positive: actual benign, predicted malicious;
- false negative: actual malicious, predicted benign;
- false-positive rate: FP divided by actual benign support;
- false-negative rate: FN divided by actual malicious support; and
- balanced accuracy: mean benign recall and malicious recall.

The report contains class precision, recall, F1 and support, macro/weighted F1,
balanced accuracy, confusion counts, and error counts/rates. Every derived
metric is a discriminated `available/value` or `unavailable/reason` object.
NaN and infinity are forbidden. A missing denominator is never presented as a
successful zero measurement.

Accuracy is not a selection metric because it can hide minority-class failures.
Each training and validation distribution records counts, proportions, minority
support, majority class, the majority-predictor accuracy, and imbalance/small-
support warnings. Small samples are marked exploratory; no scientific minimum
sample size is claimed.

## Probability and threshold interpretation

For classifiers exposing `predict_proba`, the evaluator locates the column by
the fitted class label `malicious`; it never assumes a numeric column position
and never substitutes hard predictions. Values must be finite and in `[0, 1]`.
ROC-AUC and average precision require both actual classes. Brier score and log
loss remain defined for valid single-class observations using the declared
binary label space.

Reliability bins are descriptive summaries only. No calibrator is fit, and
calibration is `not_established`. Fitting calibration on the reporting
validation data would contaminate its assessment. A future calibration process
must fit on training-derived held-out or cross-validation predictions and use
independent evaluation evidence.

Configured thresholds default to 0.3, 0.5, and 0.7 and are capped at 21. Each
validation-only row reports FP, FN, malicious precision/recall/F1, and predicted
malicious count. This analysis does not change a model or deployment threshold.
A model probability, classification threshold, and security risk assessment
are distinct concepts; probability is not labeled as risk or calibrated
confidence.

## Error analysis and privacy

Error output is aggregate-only. It includes correct, FP, and FN counts plus
groups for detected format, entropy band, and indicator presence. Groups below
five observations receive `small_subgroup_no_generalization`; this threshold is
a reporting guard, not evidence that five observations are scientifically
adequate. Reports contain no filename, hash, record ID, extracted string,
sample content, secret, or personal data.

The costs of false positives and false negatives depend on the eventual
operational context. This checkpoint documents counts and rates but does not
invent universal security costs.

## Explainability

Global permutation importance uses scikit-learn with deterministic seed,
`f1_macro`, `n_jobs=1`, and 1-20 bounded repeats. It permutes each of the 14
original validated inputs and scores the complete fitted Pipeline. Therefore,
categorical values pass through their one-hot encoder together and retain their
source feature names instead of being reported as independent dummy variables.

Importance describes how much this fitted model's validation score changes
when one column is disrupted. It is not a feature contribution for an
individual prediction and is not causal. Correlation can divide or mask
importance, particularly among `printable_string_count`,
`retained_string_count`, and `strings_truncated`. Negative importance is valid
and may indicate noise or sampling instability. Local explanations are marked
`not_implemented`; no unsupported narrative or SHAP dependency was added.

## Comparison and selection policy

Candidates are compared only when dataset digest, validation partition, label
order, feature contract, and metric definitions are common. Output is sorted by
algorithm so input iteration order cannot affect the decision.

The predeclared policy uses macro F1 as primary metric, malicious recall as a
minimum-quality check, a 0.02 primary-metric margin, and a 100-record validation
support gate. The support gate is a conservative operational policy, not a
scientific significance claim. The policy can return:

- `selected`;
- `insufficient_evidence`;
- `inconclusive_performance`; or
- `validation_failure`.

Synthetic evidence always forces abstention. Research evidence below the
support gate, unavailable primary metrics, a tie/small margin, or failure of the
declared recall floor also prevents selection. Selection would remain a research
recommendation, not registry promotion or deployment authorization.

## Artifacts and CLI

The safe output shape is:

```text
evaluations/generated/<evaluation-id>/
  evaluation_report.json
  evaluation_manifest.json
```

IDs are safe bounded path components. Export uses a staging directory, a 5 MiB
JSON limit, canonical UTF-8 JSON, SHA-256/size verification, atomic rename,
cleanup, and no overwrite. SHA-256 proves consistency with a trusted manifest,
not publisher authenticity.

From `apps/api`:

```powershell
.\.venv\Scripts\python.exe scripts\evaluate_models.py `
  --dataset ..\..\datasets\generated\lesson-set\1.0.0 `
  --output ..\..\evaluations\generated `
  --experiment-id lesson-baselines-001 `
  --evaluation-id lesson-evaluation-001 `
  --seed 42 `
  --permutation-repeats 5
```

The CLI verifies the dataset, trains and evaluates in one trusted process, and
does not deserialize model artifacts. Joblib remains pickle-compatible and
unsafe for arbitrary external input. A later lifecycle boundary must establish
trusted provenance/authenticity and compatibility before any loading.

## Future one-time test protocol

Test remains sealed in 03.04. Before a future final evaluation:

1. Freeze dataset version/digest, feature contract, fitted pipeline artifact,
   selected candidate, threshold, metrics, subgroup plan, and acceptance rules.
2. Record approvals and make the frozen evaluation plan immutable.
3. Verify trusted artifact provenance and environment compatibility without
   changing model parameters.
4. Open test exactly once and run only the predefined evaluation.
5. Publish every predefined result and limitation, including failures.
6. Prohibit post-test tuning, candidate replacement, threshold changes, or
   selective reporting. Any change creates a new research cycle and requires a
   newly governed independent test set.

This protocol is documentation, not authorization to open test now.

## Resource and evidence limits

Evaluation defaults to at most 10,000 validation records, three candidates,
five permutation repeats (maximum 20), 21 thresholds, `n_jobs=1`, and 5 MiB per
JSON artifact. There is no network, cloud execution, executable-sample access,
SHAP, hyperparameter optimization, automatic promotion, or final test metric.
Synthetic demonstrations validate integration only and cannot establish
generalization, calibration, robustness, or malware-detection capability.

## Inference boundary

Phase 03.05 references synthetic validation status in its active descriptor but
does not rerun evaluation, permutation importance, threshold selection, or
calibration per request. Global importance is not a local explanation. Phase
03.04 selected no candidate; explicit local demo registration is separate from
research selection and deployment promotion.
