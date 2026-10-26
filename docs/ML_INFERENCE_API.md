# ML Inference API

Phase 03.05 exposes one explicitly authorized local educational endpoint:

```text
POST /api/v1/ml-inferences/
multipart field: file
```

Inference is disabled by default. The only supported checkpoint mode trains a
deterministic metadata-only synthetic dataset during application lifespan,
registers one trusted Logistic Regression Pipeline in memory, and marks every
response as synthetic demonstration output. It is not production serving and
does not establish malware-detection capability.

## Configuration and local startup

```text
ICYLENS_ML_INFERENCE_ENABLED=false
ICYLENS_ML_DEMO_MODE_ENABLED=false
ICYLENS_ML_MAX_CONCURRENT_INFERENCES=2
```

Demo mode requires inference to be enabled. Values are typed; concurrency is
limited to 1-16. No model path, artifact directory, algorithm, dataset, or
candidate can be supplied through HTTP.

For an explicitly authorized local demonstration from `apps/api`:

```powershell
$env:ICYLENS_ML_INFERENCE_ENABLED="true"
$env:ICYLENS_ML_DEMO_MODE_ENABLED="true"
$env:ICYLENS_ML_MAX_CONCURRENT_INFERENCES="1"
.\.venv\Scripts\python.exe -m uvicorn app.main:app `
  --host 127.0.0.1 --port 8000
```

Configuration does not force network binding. The operator must supply
`--host 127.0.0.1`. Public exposure is not authorized by this checkpoint.

## Initialization and lifecycle

Importing `app.main` creates no model and performs no training. `create_app()`
constructs an unavailable runtime. At lifespan startup, initialization occurs
only when both inference and demo mode are true:

```text
unavailable
  -> build/verify deterministic synthetic metadata dataset
  -> train bounded baseline Pipelines through existing logic
  -> trained -> evaluated -> registered_demo
```

Registration is local demonstration authorization, not model selection. Phase
03.04 remains `selected_candidate: null`; the descriptor records
`model_selection_status: not_selected` and
`operational_detection_approved: false`. Failed initialization moves the
runtime to `rejected` and leaves the endpoint unavailable. Lifespan shutdown
clears the model and moves it to `revoked`.

The active descriptor records model/experiment/dataset identity, dataset
digest, algorithm, feature schema, preprocessing configuration, synthetic
provenance, evaluation status, authorization, and lifecycle status.

## Trusted model checks

Registration accepts only an already-fitted scikit-learn Pipeline created by
controlled application code. It verifies:

- exact `preprocessing` and `model` steps;
- supported estimator type matching the descriptor algorithm;
- sklearn fitted state;
- feature schema `1.0.0`;
- current preprocessing configuration;
- all 23 expected transformed feature names and width;
- exactly the `benign` and `malicious` fitted classes;
- callable probability output; and
- explicit synthetic demonstration authorization.

There is no `joblib.load`, `pickle.load`, `cloudpickle.load`, model upload,
auto-discovery, dynamic import, or client-selected artifact. Joblib is
pickle-compatible and unsafe for untrusted input. SHA-256 can detect changes
against trusted metadata but cannot authenticate who produced a model.

## Request flow and resources

```text
bounded multipart UploadFile
  -> existing analyze_static_upload() exactly once
     -> one 64 KiB read loop -> static report -> UploadFile closed
  -> extract_ml_features(StaticAnalysisResponse)
  -> canonical 5 numeric + 2 categorical + 7 boolean row
  -> trusted fitted Pipeline in bounded worker thread
  -> validated prediction/probability response
```

Training and evaluation never run from a request. The fitted Pipeline is reused.
No test split is accessed. Static analysis and ML training share the same
feature-vector-to-row function; identity hashes, filename, UUID, timestamps,
provenance, and labels never enter the predictive matrix.

The upload limit remains 10 MiB by default. The inference counter admits at
most the configured number of operations and returns 429 without a wait queue.
Prediction uses `asyncio.to_thread` rather than blocking the event loop.

A coroutine timeout would not stop CPU work already executing in a thread, so
this checkpoint makes no hard processing-time guarantee. Deployment still
needs whole-request limits, rate limiting, interruptible process isolation if
required, and CPU/memory/temporary-storage controls.

## Response and probability semantics

The response contains inference/analysis UUIDs, `synthetic_demo`,
`demo_only: true`, the binary prediction, benign/malicious probabilities,
`probability_calibrated: false`, trusted model provenance, and five mandatory
limitations.

The fitted `classes_` values map probability columns by label. Output must have
shape `(1, 2)`, finite values in `[0, 1]`, sum within `1e-9` of one, and argmax
consistent with `predict`. Values are not independently calibrated and are not
a risk score, safety confidence, or verified finding. The synthetic model can
label harmless text `malicious`; that demonstrates why it must not be
operationalized.

The response contains no filename, sample hash, raw bytes, strings, source
path, local feature contribution, `safe`/`clean` verdict, or risk score. Global
permutation importance is not presented as the reason for one prediction.

## HTTP behavior

| Condition | Status |
|---|---:|
| Authorized demo and valid file | 200 |
| Missing file or malformed multipart | 4xx / 422 |
| Empty file or invalid filename | 422 |
| Upload over configured limit | 413 |
| Inference capacity exhausted | 429 |
| Inference disabled or no compatible model | 503 |
| Unexpected internal failure | generic 500 |

Initialization/configuration failures are not client 422 errors. Unexpected
logs contain only exception type, never exception text, content, strings, or
model internals.

## Reproducibility and boundaries

In the documented environment, identical bytes with equivalent filename format
semantics produce the same 14 observations, label, and probabilities regardless
of base filename or chunk segmentation. Inference and analysis UUIDs differ.
Exact floating-point reproducibility is not promised across dependency, OS,
architecture, CPU library, or estimator-version changes.

There is no persistent sample, network call, executable-content handling, test
evaluation, tuning, calibration, SHAP, per-request permutation importance,
registry/promotion, distributed worker, or public deployment.
