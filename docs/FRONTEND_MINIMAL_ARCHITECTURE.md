# FRONTEND MINIMAL ARCHITECTURE (FE-01)

## Structure
`
apps/web/
  astro.config.mjs
  package.json
  src/
    components/
      FileAnalysisApp.tsx
      FileUploader.tsx
      ResultPlaceholder.tsx
    layouts/
      BaseLayout.astro
    lib/
      api.ts
    pages/
      index.astro
    styles/
      global.css
    env.d.ts
`

## Principles
- Single-page experience (one route: /)
- Astro for shell, React islands for interactivity
- Minimal dependencies (Astro, React, Tailwind v4 via Vite plugin)
- No client-side persistence, no history, no authentication
- No backend calls in FE-01 (UI only)
- Prepared components for future integration without inventing data

## API layer
- src/lib/api.ts provides a minimal fetch wrapper with base URL via PUBLIC_API_BASE_URL (default http://127.0.0.1:8000), timeout/abort support, and basic error normalization. Not used in FE-01.

## Build
- `npm ci` installs the locked dependency graph with Node.js `>=22.23.4`.
- `npm run check`, `npm run typecheck`, `npm run lint`, `npm run format`, and
  `npm test` validate the baseline.
- `npm run build` produces the ignored static site in `dist/`.

## FE-01.1 recovery

The recovery checkpoint corrected malformed TypeScript in `src/lib/api.ts`,
added explicit local quality scripts and component tests, and removed nested
Git metadata from `apps/web` after preserving it outside the repository. No
backend integration was added.
