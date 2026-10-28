# Frontend UX/UI Redesign

## Initial audit

FE-04 began on `main` at `f48821640046e1364e16462b44a6af18fee5aeb7`. The working tree already contained parallel changes to repository documentation and `tmp/`; those files were preserved. FastAPI was inspected only to confirm the existing health contract and was not modified.

The functional frontend was technically sound but presented every result as an equal-width card inside a `max-w-2xl` column. This left desktop space unused, separated the fingerprint from file identity, kept the large uploader above completed results, and gave primary data, explanations, ML, and limitations nearly identical visual weight. Tokens covered only one accent color, and component styling mixed repeated neutral values with local utility classes.

## Design direction

iCYLENS is presented as an interactive research instrument rather than a commercial antivirus or SOC dashboard. The composition uses a near-black foundation, restrained blue accent, thin borders, compact monospace metadata, large editorial typography, and asymmetric content regions. There are no threat gauges, animated backgrounds, security scores, decorative charts, or fabricated states.

Central CSS tokens define background, surfaces, borders, primary/secondary/muted text, accent, success, warning, error, radii, shadow, timing, and typography. Success and error colors communicate connectivity or request state only; they never classify a file.

## New structure

The page shell now supports up to 1400 px and contains:

1. A minimal brand header with a real FastAPI health indicator.
2. A focused editorial introduction.
3. A stateful upload workbench.
4. An asymmetric 12-column result grid.
5. A concise academic boundary footer.

Completed results are organized into File identity, Static analysis, Technical pipeline, and Scientific limitations. The FE-03 synthetic ML demonstration remains a visually secondary laboratory panel and is clearly separated from the static result.

File identity consolidates detected format, filename, MIME, size, validation, extension consistency, and the copyable SHA-256 value. Static analysis places the mathematically valid entropy scale alongside exact string and indicator observations. The conceptual pipeline retains expandable stages and the explicit non-trace disclaimer. Every backend limitation remains visible.

## Upload experience

The empty uploader is the initial focal point and exposes drag-and-drop, file picker activation, the 10 MiB bound, and the no-execution boundary. After selection it becomes a compact file identity row with size, removal, and the primary analysis action. Analyzing uses an indeterminate pulse and textual status—never a fabricated percentage—and retains cancellation. Error state keeps the selected file and presents Retry. On completion, the workbench collapses to a small replacement control so results become dominant; Analyze again remains available.

## Visualization refinements

- Entropy preserves the direct `value / 8` mapping, exact numeric value, units, accessible meter semantics, and scientific caveat.
- Static counts remain separate metric cards. The only proportional feature bar compares retained strings with the configured same-unit cap.
- Indicators use a bounded scroll region for dense responses without hiding the count or truncation state.
- The pipeline changes layout at desktop, tablet, and mobile breakpoints without implying measured time or sequence duration.
- Synthetic ML provenance and limitations remain adjacent to the optional action and response.

## Responsive behavior

At wide desktop sizes, static analysis and the pipeline use an 8/4 split, while ML and limitations use a subordinate 5/7 split. Below 1040 px, panels become full-width and the pipeline becomes a two-column concept list. Below 720 px all content becomes one column, identity and entropy dividers change direction, controls stack, hashes wrap, and limitation entries remain fully readable. Below 430 px feature metrics stack and the header removes nonessential brand subcopy.

Rendered browser validation found no horizontal overflow at 1920, 1440, 768, 390, or 375 px, including an extreme filename, 18 indicators, a long SHA-256 value, and seven extended limitation descriptions.

## Accessibility and interaction

The page includes a skip link, semantic landmarks and headings, native buttons, keyboard-operable upload and pipeline controls, focus-visible outlines, live status regions, textual equivalents for meters, adequate touch targets, and color-independent labels. The real connection indicator begins in a neutral checking state and reports connected only after a valid `{ status: "healthy" }` response. Reduced-motion changes the processing pulse from 1.2 seconds to 0.00001 seconds and disables smooth scrolling.

## Security and privacy

The redesign changes presentation only. It adds one read-only request to the existing local health endpoint. Upload and analysis contracts are unchanged. No sample persistence, active preview, byte logging, unsafe HTML, third-party transmission, secret, browser model execution, or threat verdict was introduced.

## Component changes

- `BackendStatus.tsx`: real health-backed header state.
- `FileAnalysisApp.tsx`: workbench state composition and completed-result hierarchy.
- `FileUploader.tsx`: initial, selected, compact, drag, keyboard, and removal presentation.
- `ResultPlaceholder.tsx`: consolidated identity and asymmetric results grid.
- Existing entropy, static-feature, pipeline, and ML components received presentation-only refinements.
- `global.css`: centralized tokens, responsive system, focus states, and reduced motion.

No charting or design-system dependency was added. Existing Lucide icons are used sparingly for operational controls.
