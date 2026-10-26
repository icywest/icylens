# Phase 03 / Checkpoint 03.05 Acceptance

Status: **PASS**  
Date: 2026-10-25

## A. Initial audit

The repository was clean on `main`. The baseline reproduced 352 tests, 94.11%
coverage, Ruff, strict mypy, `pip check`, and unified Quality Gate PASS. Existing
training retained fitted Pipelines in process and never loaded joblib; evaluation
used validation only and selected no candidate. No inference endpoint or model
lifecycle existed.

## B. Implementation

Created:

- `apps/api/app/api/v1/routes/ml_inferences.py`
- `apps/api/app/ml/demo.py`
- `apps/api/app/ml/model_runtime.py`
- `apps/api/app/schemas/ml_inference.py`
- `apps/api/app/services/ml_inference.py`
- `apps/api/tests/test_ml_inference_api.py`
- `docs/ML_INFERENCE_API.md`
- `docs/PHASE_03_CHECKPOINT_03_05_ACCEPTANCE.md`

Modified:

- `apps/api/.env.example`
- `apps/api/app/api/v1/router.py`
- `apps/api/app/core/config.py`
- `apps/api/app/main.py`
- `apps/api/app/ml/preprocessing.py`
- `apps/api/tests/conftest.py`
- `apps/api/tests/test_analysis_contracts.py`
- `apps/api/tests/test_project_security.py`
- `README.md`
- `docs/API_CONTRACTS.md`
- `docs/ARCHITECTURE.md`
- `docs/DEVELOPMENT_LOG.md`
- `docs/ML_MODEL_EVALUATION.md`
- `docs/ML_TRAINING_PIPELINE.md`

Deleted: none. Unrelated changes: none.

## C. Runtime architecture

`create_app()` creates an unavailable runtime without training. When both demo
flags are true, lifespan builds and verifies a deterministic 40-record synthetic
metadata dataset, invokes existing training once, validates the fitted Logistic
Regression Pipeline, and explicitly registers it. Requests reuse that object.

```text
multipart file
  -> analyze_static_upload() once / one bounded read / cleanup
  -> StaticAnalysisResponse
  -> extract_ml_features()
  -> shared canonical 14-feature row
  -> trusted Pipeline in bounded worker thread
  -> strict MLInferenceResponse
```

## D. Model lifecycle

The real demo transition is `unavailable -> trained -> evaluated ->
registered_demo`. Initialization failure produces `rejected`. Shutdown clears
the active object and produces `revoked`. Disabled or unconfigured processes
remain unavailable.

The immutable active descriptor includes model, experiment, algorithm, feature
and preprocessing contracts, dataset ID/digest, synthetic provenance,
validation status, explicit demo authorization, `not_selected`, and
`operational_detection_approved: false`.

## E. Security validation

Application and scripts contain no `joblib.load`, `pickle.load`,
`cloudpickle.load`, model auto-discovery, upload, dynamic import, or HTTP model
path. Tests monkeypatch loading, training, and network functions to fail during a
request; inference still succeeds. Registration verifies fitted state, exact
steps, estimator/algorithm match, schema, exact 23 transformed names, binary
classes, probability support, and authorization.

## F. Inference response

Actual loopback response for harmless text (UUIDs vary):

```json
{
  "inference_mode": "synthetic_demo",
  "demo_only": true,
  "status": "completed",
  "prediction": {
    "label": "malicious",
    "probability_estimates": {
      "benign": 0.4789047360305032,
      "malicious": 0.5210952639694968
    },
    "probability_calibrated": false,
    "interpretation": "model_output_not_security_verdict"
  },
  "model": {
    "model_id": "builtin-synthetic-logistic-demo-v1",
    "algorithm": "logistic_regression",
    "experiment_id": "builtin-synthetic-inference-demo-v1",
    "feature_schema_version": "1.0.0",
    "dataset_id": "builtin-synthetic-inference-demo",
    "dataset_integrity_digest": "5601e9facd56a3b41021e4a4355e7198c707c441c6f87897a26481d5c3168025",
    "dataset_provenance_type": "synthetic",
    "evaluation_status": "synthetic_validation_only",
    "model_selection_status": "not_selected",
    "lifecycle_status": "registered_demo",
    "operational_detection_approved": false
  }
}
```

The harmless sample being labeled `malicious` is not a finding; it demonstrates
that the synthetic toy model must not be operationalized. The complete response
also contains fresh inference/analysis UUIDs and all five required limitations.

## G. API validation

Real Uvicorn was bound only to `127.0.0.1` on isolated validation ports. Default
configuration returned 503. Explicit demo returned 200. Missing file returned
422, an upload one byte over 10 MiB returned 413, and OpenAPI exposed the route.
Automated tests additionally verify invalid filename/empty/malformed input,
429 capacity, unavailable/rejected models, generic 500 responses, closure, and
all prior endpoints.

Only validation PIDs 20556 and 27564 were stopped. An existing unrelated user
Uvicorn process was not modified.

## H. Reproducibility

Repeated inference over identical bytes produced identical label and probability
objects and different UUIDs. Different base filenames with equivalent extension
semantics and different stream chunk segmentation also matched. Both streams
were read once and closed. Probability mapping uses fitted `classes_`; shape,
finiteness, range, sum tolerance `1e-9`, and predict/argmax consistency are
enforced.

Floating-point equality outside the documented dependency/platform environment
is not promised.

## I. Quality Gate

- Baseline tests: **352**.
- New focused tests: **36**.
- Total: **388 passed**.
- Total statement/branch coverage: **93.91%**.
- Ruff lint/format: **PASS**.
- Mypy strict: **PASS**, 62 source files.
- `pip check`: **PASS**.
- Unified Quality Gate: **PASS**.

The coverage floor remains 85%.

## J. Security findings

Controls include disabled defaults, explicit dual opt-in, lifespan-only
training, one active model, non-queuing concurrency, worker-thread prediction,
bounded upload/extraction, unconditional cleanup, strict probability mapping,
content-free unexpected errors, local-only operation, and no test access.

Residual deployment risks include Starlette multipart spooling before service
limits, absence of authentication/rate limits, thread work not being cancelled
by coroutine timeout, CPU/memory concurrency across multiple processes, model
supply-chain authenticity for any future artifact loader, and floating-point
platform drift. Public deployment is not authorized. No open Critical/High
finding remains inside the scoped local demo.

## K. Architecture explanation

1. Training fits model parameters; inference reuses frozen fitted parameters on
   a new observation.
2. Preprocessing must be identical so categories, scaling, order, types and 23
   transformed columns retain training meaning.
3. Joblib uses pickle-compatible deserialization, which can execute attacker-
   controlled code before a model is inspected.
4. SHA-256 proves bytes match a trusted digest, not who authored or authorized
   those bytes.
5. A synthetic model has no credible real-world validation and cannot emit a
   verified malware or safety verdict.
6. Demo authorization requires both typed flags and successful lifespan
   registration of the internally created Pipeline.
7. FastAPI calls the existing static-analysis service once, then adapts its
   typed report into canonical features without rereading the upload.
8. The lifecycle separates trained/evaluated/registered/rejected/revoked states,
   providing a future boundary for authenticated real-model admission.
9. A probability is an estimator output; without independent calibration and
   operational context it is not a calibrated confidence or risk score.

## L. Final decision

**PASS.** The local endpoint, single-pass extraction, trusted in-memory model,
strict compatibility/probability checks, explicit synthetic semantics, bounded
capacity, deterministic behavior, security tests, Uvicorn demonstration, and
quality gates are verified.

## M. Version-control handoff

No `git add`, commit, tag, or push was run. Suggested commits:

- `feat(ml): add trusted in-memory inference lifecycle`
- `feat(api): expose bounded synthetic ML inference endpoint`
- `test(ml): verify inference compatibility security and reproducibility`
- `docs(ml): document inference API and checkpoint acceptance`

## N. Next step

**Phase 03 / Checkpoint 03.06 - Comprehensive ML Audit & Phase Acceptance.**

It was not implemented automatically.
