# PHASE 03 ACCEPTANCE (Checkpoint 03.06)

**Date:** 2026-10-25  
**Repo:** C:\icylens | Branch: main | Backend: C:\icylens\apps\api  
**Auditor:** opencode (read-only)

## Acceptance Criteria Check

| Criterion | Status | Evidence |
|---|---|---|
| Feature schema v1.0.0 contract (14?23) | PASS | `app/schemas/ml_features.py`, `app/ml/preprocessing.py` |
| Dataset governance/splitting with isolation | PASS | `app/ml/splitting.py`, `app/ml/builder.py` |
| Training on training split only | PASS | `app/ml/training.py` (fits training_matrix only) |
| Validation/evaluation on validation split only | PASS | `app/ml/evaluation.py` (uses validation partition) |
| Test set sealed (no leakage) | PASS | Partition checks in training/eval; selection uses validation only |
| Explainability (permutation importance) on validation | PASS | `app/ml/evaluation.py::_feature_influences` |
| Conservative selection policy (blocks synthetic) | PASS | `select_candidate` returns `insufficient_evidence` for `synthetic_demo` |
| Trusted in-memory inference only (no unsafe load) | PASS | `app/ml/model_runtime.py`, no `pickle.load`/`joblib.load` in app/tests |
| Synthetic/demo strictly gated and non-promotable | PASS | Schema locks + `validate_trusted_pipeline` requires synthetic+authorized |
| Inference API bounded (concurrency/limits/errors) | PASS | `app/services/ml_inference.py`, `app/api/v1/routes/ml_inferences.py` |
| All limitations present in response | PASS | Schema validator requires all 5 codes |
| Integrity/reproducibility metadata | PASS | Manifests, experiment/eval artifacts, digests, versions |
| Quality Gate | PASS | 388 passed, 93.91% coverage, Ruff/Mypy/pip check PASS |

## Explicit Decisions

### 1) Acceptance of infrastructure for local educational use
**ACCEPTED** as a **local educational ML inference platform**.  
Rationale: Strong contracts, isolation, safe runtime, explicit limitations, high test coverage.

### 2) Scientific validity as a real malware detector
**NOT VALIDATED. NOT ACCEPTABLE AS A CLAIM.**  
Rationale: Trained/evaluated only on synthetic metadata in demo path; selection blocked for synthetic; no real-world validation, calibration, or adversarial evaluation claimed. Probabilities explicitly not calibrated and not a security verdict.

### 3) Preparation for public deployment
**NOT READY.**  
Blockers/requirements before public exposure:
- Replace synthetic demo with vetted real datasets under proper governance/legal review
- Implement secure artifact loading with signing/allowlist (if moving from in-memory)
- Calibrate probabilities and define operational thresholds with validation
- Conduct adversarial testing, robustness evaluation, and abuse controls
- Define incident response, rate limiting beyond local capacity, and monitoring
- Remove or strictly gate any path that could be misread as production detection
- Legal/compliance review (data handling, licensing)

## Required Usage Constraints (Must Remain)
- `ML_INFERENCE_ENABLED=True` and `ML_DEMO_MODE_ENABLED=True` required for demo
- Only synthetic data authorized
- `operational_detection_approved` must remain `False`
- All 5 limitations must be returned
- No test set used for training/selection/tuning

## Final Quality Gate
- **Command:** `.\.venv\Scripts\python.exe scripts/quality_gate.py` (from `apps/api`)
- **Result:** **QUALITY GATE: PASS**
- **Details:** 388 passed in 22.01s, coverage 93.91%, pip check OK

## Deliverables
- `docs/PHASE_03_AUDIT_REPORT.md` (created)
- `docs/PHASE_03_ACCEPTANCE.md` (created)
