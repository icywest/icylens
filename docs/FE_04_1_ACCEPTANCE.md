# FE-04.1 Acceptance

## Decision

FE-04.1 replaces the rejected FE-04 visual direction with a traditional, light-first, teal-branded file analysis interface. Functional behavior remains unchanged.

## Acceptance evidence

- Light `#f7f8f9` background and white software surfaces replace the dark theme.
- `#0096a1` is the restrained brand/focus/visualization reference; darker `#007f89` supports accessible action contrast.
- Header is limited to iCYLENS, File Analysis Lab, and real API state.
- Page title is moderate and descriptive rather than promotional.
- Upload is a compact conventional form with a visible Choose file action.
- File data uses a label/value property table.
- Results form a simple vertical section stack rather than a dashboard grid.
- Entropy, static observations, pipeline, synthetic ML boundaries, and scientific limitations remain intact.
- ML is visually secondary and explicitly educational/synthetic.
- No giant cards, neon effects, gradients, glassmorphism, decorative status badges, sidebar, or fabricated security score remains.

## Functional preservation

Picker upload, drag-and-drop, local validation, file removal, replacement, Analyze File, Analyze again, Retry, Cancel, stale-response protection, FastAPI requests, health checking, Zod validation, SHA-256 copy feedback, entropy/static visualizations, synthetic ML separation, and every backend limitation remain covered by the existing test suite and browser workflow.

## Browser validation

Headless Microsoft Edge rendered and visually inspected the initial, selected, analyzing, completed, error, and mobile states at 1920, 1440, 768, 390, and 375 px. No horizontal overflow was detected. Long filenames and hashes wrapped or truncated according to context. Reduced motion was verified at `0.00001s`.

## Security and independence

No FastAPI file was modified. No sample persistence, execution, preview, third-party upload, unsafe HTML, new endpoint, analytical capability, ESET asset, trademark claim, certification, or affiliation was added.

## Quality gate

- Vitest: 46 tests passed across 9 files.
- Astro check: 0 errors, 0 warnings, 0 hints.
- TypeScript, ESLint, and Prettier: passed.
- Production build: passed; one static page generated.
- npm audit: 0 vulnerabilities.
- Real Microsoft Edge visual validation: passed at all required widths and states.

## Files

- `apps/web/src/pages/index.astro`
- `apps/web/src/layouts/BaseLayout.astro`
- `apps/web/src/styles/global.css`
- `apps/web/src/components/FileAnalysisApp.tsx`
- `apps/web/src/components/FileUploader.tsx`
- `apps/web/src/components/ResultPlaceholder.tsx`
- Existing visualization components and regression tests
- `docs/FRONTEND_TRADITIONAL_UI_DESIGN.md`
- `docs/FE_04_1_ACCEPTANCE.md`
