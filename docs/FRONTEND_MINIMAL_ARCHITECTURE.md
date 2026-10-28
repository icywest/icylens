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
- npm run build produces static site in dist/
