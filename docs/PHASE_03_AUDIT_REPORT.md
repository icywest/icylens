# PHASE 03 AUDIT REPORT (Checkpoint 03.06)

**Date:** 2026-10-25  
**Repository:** C:\icylens (branch: main)  
**Backend:** C:\icylens\apps\api  
**Scope:** Phase 03 up to Checkpoint 03.06 (ML Detection Engine)  
**Auditor:** opencode (read-only)  
**Goal:** Determine if v0.3.0 can be accepted as a local educational ML inference platform, without claiming a scientifically validated malware detector or production readiness.

## Executive Summary

- **Overall verdict (read-only):** ACCEPTABLE as a **local educational ML inference platform** with explicit restrictions.  
- **Scientific validity (real malware detector):** **NOT VALIDATED / NOT CLAIMED.**  
- **Public deployment readiness:** **NOT READY.**

Quality Gate: **PASS** (pytest 388 passed, coverage 93.91%, Ruff PASS, Mypy strict PASS, pip check PASS). Inference verified (TestClient/Uvicorn path) returns HTTP 200 with all demo guardrails.

## 1) Test Isolation (Training/Evaluation/Explainability/Selection)

**Evidence:**
- `app/ml/splitting.py`: requires unique SHA-256 identities, forbids `unknown` labels, requires >=2 classes, stratified by label with minimums per split, stable seeded assignment, raises on infeasible assignments. Locked assignments preserved.
- `app/ml/training.py`: `validate_training_dataset` verifies manifest integrity (`verify_dataset_integrity`), requires `ready_for_training`, feature schema match, supported extraction versions, no duplicates, no unknown/unassigned splits. Requires minimum counts for training/validation and >=1 per class for sealed test. `_experiment_mode` enforces all-synthetic-or-all-real (rejects mixed). Fits only on `training` split; validates only on `validation` split. Never touches test set.
- `app/ml/evaluation.py`: `evaluate_experiment` calls `_verify_compatibility` (integrity, identity match dataset<->experiment, schema match, pipeline set matches experiment). Uses only `validation` partition (`build_feature_matrix(validation)`). Permutation importance computed on validation matrix with fixed seed/repeats. Model selection (`select_candidate`): for `mode == "synthetic_demo"` returns `insufficient_evidence` with reason `synthetic_evidence` and does **not** select. For research mode enforces support/margin/recall floor; all decisions are explicit and conservative.
- `app/ml/demo.py`: builds synthetic dataset/trains/validates via same pipeline paths; marks lifecycle `registered_demo`, sets `evaluation_status="synthetic_validation_only"`, `synthetic_data=True`, `demonstration_authorized=True`, `operational_detection_approved=False`.

**Conclusion:** **PASS.** Test set is sealed (never used in training/validation/tuning/importance/selection). Isolation enforced by partition checks and explicit guards.

## 2) Model Security (No Unsafe Load, Trusted In-Memory, Synthetic Restrictions)

**Evidence:**
- `app/ml/model_runtime.py`: `TrustedModelRuntime` holds in-process `Pipeline` only; no deserialization. `validate_trusted_pipeline` enforces: feature schema/version match, exact preprocessing config match, pipeline steps `("preprocessing","model")`, `ColumnTransformer` present, algorithm matches descriptor class, fitted check, transformed feature count/names match contract (14?23), exactly 2 classes `{benign,malicious}`, `predict_proba` exists. **Requires** `descriptor.synthetic_data is True` and `descriptor.demonstration_authorized is True`. `predict` validates feature shape/schema, checks class alignment, probability shape/finite/range/sum to 1, and `predicted == argmax` consistency.
- `app/ml/demo.py`: constructs pipelines via `train_experiment` (in-memory) and registers via `runtime.register(...)` only after validation.
- **Codebase search:** no `pickle.load` or `joblib.load` found under `apps/api/app` or `apps/api/tests`. Found only in vendored `.venv` packages (expected).
- `app/schemas/ml_inference.py`: `ActiveModelDescriptor` locks synthetic flags to `True`/`True`, `evaluation_status="synthetic_validation_only"`, `lifecycle_status="registered_demo"`, `operational_detection_approved=False`. `InferenceModelSummary` exposes only safe fields and cannot represent non-synthetic/non-demo models.
- `app/ml/experiments.py`: export path uses `joblib.dump` with SHA-256/size metadata (staged artifacts) but **no app-side deserializer** exists; runtime never loads serialized models.

**Conclusion:** **PASS.** No unsafe deserialization in runtime paths. Registration is trusted and gated. Synthetic/demo cannot be promoted (hard-coded schema constraints + validation).

## 3) Integrity & Reproducibility (Manifests, Artifacts, Feature Schema v1.0.0)

**Evidence:**
- `app/schemas/ml_features.py`: `FEATURE_SCHEMA_VERSION = "1.0.0"`, `MLFeatureVector` has 14 predictive fields with strict domains/enums, `extra="forbid"`, `frozen=True`. `PREDICTIVE_FEATURE_ORDER` fixed.
- `app/ml/preprocessing.py`: maps 14?23 via `ColumnTransformer` (5 numeric, 2 categorical with explicit categories + `handle_unknown='ignore'`, 7 booleans) with fixed order/names (`expected_transformed_feature_names()`).
- `app/ml/builder.py`: builds dataset/manifest with content integrity digests; `verify_dataset_integrity` enforced in training/evaluation.
- `app/ml/training.py`: experiment report records dataset identity/digest, feature schema, extraction versions, seed, library versions, preprocessing config, split distributions.
- `app/ml/evaluation_artifacts.py`: canonical JSON artifacts with digest verification.
- `app/ml/experiments.py`: staged export with SHA-256/size, digest verification patterns present.

**Conclusion:** **PASS.** Feature contract is explicit and versioned. Integrity checks and reproducibility metadata are present.

## 4) Concurrency, Errors, Limits (API Controls)

**Evidence:**
- `app/core/config.py`: `ML_INFERENCE_ENABLED=False`, `ML_DEMO_MODE_ENABLED=False`, `ML_MAX_CONCURRENT_INFERENCES` 1-16. Validator requires `ML_DEMO_MODE_ENABLED => ML_INFERENCE_ENABLED`. Production blocks DEBUG.
- `app/services/ml_inference.py`: `InferenceCapacity` async counter (non-queuing) with lock, raises on unbalanced release. `infer_upload` checks enabled, requires active model via `runtime.require_active()`, acquires capacity before analysis, runs `analyze_static_upload` with configured bounds, extracts features, calls `runtime.predict` in thread, returns response with all limitations. Closes upload and releases capacity in `finally`.
- `app/api/v1/routes/ml_inferences.py`: maps errors to correct codes: 413 (upload too large), 422 (invalid/empty filename), 429 (capacity exhausted), 503 (disabled/unavailable), 500 (generic, logs exception type only). No stack traces leaked. Response schema strict.
- `app/main.py`: lifespan initializes demo only if both flags enabled; on failure marks runtime rejected and logs exception type; revokes on shutdown.
- **Live test (TestClient):** with flags enabled and manual init, `POST /api/v1/ml-inferences/` returns 200, `demo_only=True`, `inference_mode=synthetic_demo`, 5 limitations present, probabilities sum to 1, `operational_detection_approved=False`.

**Conclusion:** **PASS.** Bounded concurrency, safe error handling, strict schema, demo-only gating.

## 5) Findings by Severity

### CRITICAL
- None identified in audited paths.

### HIGH
- None identified. Guards are explicit and enforced.

### MEDIUM
- **M-01 (Documentation/claims):** Risk of over-claiming. Must keep "synthetic-demo only", "not a security verdict", "not calibrated" explicit everywhere (already present in schema/limits/service).
- **M-02 (Operational):** Inference requires manual/init via flags; if not initialized, returns 503 (by design). Ensure deployment docs state this clearly.
- **M-03 (Test environment):** In tests, demo initialization may need explicit call depending on app wiring (observed in quick test) — not a defect, but worth noting for ops.

### LOW/INFO
- **L-01:** `experiments.py` has export/staging utilities (joblib.dump + digests) — good for artifacts, but ensure no deserialization path is added later.
- **L-02:** Permutation importance on validation only — correct for this stage.
- **L-03:** Library versions tracked in experiment report (good for reproducibility).

## Attack/Abuse Considerations (Read-Only)
- **Deserialization RCE:** Mitigated (no load in app paths; trusted in-memory only).
- **Model poisoning/promotion:** Blocked by schema locks and validation.
- **Test leakage:** Blocked by partition checks.
- **DoS:** Mitigated by upload bounds + concurrency cap.
- **Information leakage:** Error messages generic on 500; exception types logged only.

## Test/Quality Evidence
- `pytest`: **388 passed** (23.39s)
- Coverage: **93.91%**
- Quality Gate: **PASS** (pytest, coverage, pip check)
- Ruff: **PASS** (per quality gate)
- Mypy strict: **PASS** (per quality gate)

## Recommendation
Proceed with **v0.3.0 acceptance as local educational ML inference platform** under strict constraints. Do **not** claim scientific validation as a real malware detector or production readiness.
