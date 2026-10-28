# FE-03 Acceptance

## Decision

Accepted: interactive technical visualizations are integrated with real FE-02 static-analysis output. ML is an explicit opt-in synthetic educational action, remains unavailable under default backend configuration, and is never presented as operational detection.

## Acceptance evidence

- The repository and current dirty state were audited before edits. Existing Phase 06.07 and FE-01/FE-02 work was preserved; no Git recovery operation was performed.
- Static and ML routes, schemas, service flow, feature contract, configuration defaults, tests, and documentation were inspected.
- Entropy is shown on the contract-defined 0–8 bits/byte scale with exact numeric and accessible text values.
- Static counts use their real units. The retention bar uses only retained strings divided by the backend-declared retention cap.
- Zero indicators and missing/invalid entropy have explicit empty states. String and indicator truncation are disclosed independently.
- The six-stage pipeline is expandable by keyboard and explicitly conceptual rather than a backend execution trace.
- No risk threshold, verdict, fake confidence, invented timing, arbitrary score, or per-file feature importance was added.
- The page remains a focused single-file analysis workflow with one technical accent and no visualization library.
- Responsive CSS collapses the feature grid on narrow screens, wraps long content, and honors reduced motion.

## ML compatibility finding

The ML route is `POST /api/v1/ml-inferences/` with multipart field `file`, so it accepts a file directly. It invokes static analysis exactly once within that separate request and consumes the canonical 14-feature schema. It does not accept the FE-02 analysis response or analysis ID, so combining outputs would require uploading/analyzing the file again.

The endpoint is disabled by default and available only when both inference and demo flags are explicitly enabled. The response contract mandates synthetic provenance, uncalibrated probabilities, `model_selection_status: not_selected`, `operational_detection_approved: false`, and five limitations. FE-03 calls it only after the user selects the separate synthetic-demo action; it validates those invariants before rendering and handles 503 as unavailable.

## Validation record

- Frontend: 43 Vitest tests passed across 8 files.
- Backend contract regression: 69 static-analysis and ML-inference tests passed.
- Astro check: 0 errors, 0 warnings, 0 hints.
- TypeScript, ESLint, Prettier, production build, and npm audit passed; npm audit reported 0 vulnerabilities.
- Real-browser E2E: headless Microsoft Edge passed upload/analyze, independent SHA-256 comparison, entropy range, pipeline interaction, ML-unavailable handling, mobile/desktop layouts, and backend-offline handling.

## Files added or materially changed

- `apps/web/src/components/EntropyVisualization.tsx`
- `apps/web/src/components/StaticFeatureVisualization.tsx`
- `apps/web/src/components/AnalysisPipeline.tsx`
- `apps/web/src/components/MLPredictionVisualization.tsx`
- `apps/web/src/components/ResultPlaceholder.tsx`
- `apps/web/src/styles/global.css`
- Component tests for each visualization and expanded result integration tests
- `docs/FRONTEND_TECHNICAL_VISUALIZATIONS.md`
- `docs/FE_03_ACCEPTANCE.md`
