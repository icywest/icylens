# Frontend Technical Visualizations

## Scope

FE-03 visualizes values returned by the completed FE-02 static-analysis request. It adds no charting dependency, storage, or inferred security assessment. The optional synthetic ML action is the only secondary upload and is clearly disclosed before activation. CSS provides the small number of scales and responsive layouts.

## Capability matrix

| Capability | Backend supported | File-linked | Frontend visualization |
|---|---|---|---|
| Upload validation | Yes, bounded multipart upload | Yes | File overview and conceptual Validation stage |
| Format identification | Yes, leading-signature and extension consistency | Yes | Exact format/consistency values and Identification stage |
| SHA-256 fingerprint | Yes | Yes | Copyable exact digest and Fingerprinting stage |
| Shannon entropy | Yes, finite 0–8 bits/byte | Yes | Literal 0–8 scale, numeric/text equivalent, measured byte count |
| Printable-string statistics | Yes, bounded observed/retained counts | Yes | Exact count cards and retained/configured-cap scale |
| Informational indicators | Yes, bounded list | Yes | Exact count, category/description list, empty and truncation states |
| Static-analysis limitations | Yes | Yes | Backend descriptions plus boundaries in the conceptual pipeline |
| ML inference | Yes, separate multipart endpoint | Yes, but it re-analyzes a separate upload | Explicit opt-in synthetic demo with strict response validation and unavailable state |
| ML feature importance | No per-file contract | No | Omitted |
| Operational security verdict | No | No | Omitted |

## Visualization semantics

`EntropyVisualization` maps the backend value directly to `value / 8`. Its accessible meter exposes a minimum of 0, maximum of 8, current value, and a bits-per-byte text equivalent. The accent is neutral cyan; there are no good/bad colors, thresholds, bands, or labels. Entropy is byte-distribution information, not a risk score.

`StaticFeatureVisualization` presents observed strings, retained summaries, and retained indicators as exact counts. Its only proportional bar is `retained_count / maximum_retained_strings`, two same-unit fields explicitly supplied by the backend. The view says this is configured capacity, not severity. It discloses string and indicator truncation independently and does not interpret zero indicators as safety.

`AnalysisPipeline` contains six expandable stages: Validation, Identification, Fingerprinting, Feature Extraction, Static Analysis, and Interpretation. Each exposes a description, a result-backed datum, and a limitation. Buttons use native keyboard behavior and `aria-expanded`/`aria-controls`. The component labels itself a conceptual model and never invents trace events, timestamps, or duration.

## ML boundary

`POST /api/v1/ml-inferences/` accepts the same multipart field name and runs the existing static analyzer internally, so it is technically file-linked. It is nevertheless disabled by default (`ML_INFERENCE_ENABLED=false`, `ML_DEMO_MODE_ENABLED=false`). Its only authorized model is trained on synthetic metadata, its probabilities are uncalibrated, its lifecycle says `not_selected`, and `operational_detection_approved` is false.

FE-03 therefore makes no automatic ML request. An explicitly labeled button can send the selected file to the separate endpoint. Default configuration produces a clear unavailable state. When an authorized local demo is enabled, the UI validates the complete response, labels the output and dataset provenance as synthetic, identifies the model/algorithm/schema, calls both class values uncalibrated probability estimates, and renders all five backend limitations. It does not transform entropy into a prediction, expose the synthetic label as a verdict, display probabilities as confidence/risk, or invent local feature importance.

## Accessibility and responsive behavior

Every visual value has visible text. Meter roles expose exact bounds and values. Pipeline controls are buttons, focus-visible, and keyboard operable. Long values wrap; the feature grid collapses to one column below 32rem. The global reduced-motion rule suppresses nonessential animation and transition duration.

## Security and privacy

Static visualizations receive the already-validated in-memory response and make no network calls. The optional ML action sends the selected file only to the configured FastAPI endpoint after explicit activation. The frontend executes no content, renders no raw HTML, sends nothing to third parties, and persists nothing. Indicator evidence remains governed by the backend response; the visualization currently presents only category and description.

## Performance and verification

No visualization library was added. The production build remains one static Astro page, and visual updates use small React components plus CSS. FE-03 is covered by runtime-schema, component, integration, accessibility-semantic, unavailable-state, cancellation, stale-response, and persistence tests. A real headless Microsoft Edge workflow also exercised upload, analysis, independently verified SHA-256, entropy, pipeline expansion, the default ML-unavailable response, mobile/desktop layouts, and the backend-offline state.
