# iCYLENS frontend

Minimal Astro and React frontend for the iCYLENS academic file-analysis demo.
FE-02 sends one explicitly selected file to the local FastAPI static-analysis
endpoint and presents its validated technical results and limitations.

## Requirements

- Node.js `>=22.23.4`
- npm (the lockfile was validated with npm 11)

## Reproduce the baseline

```sh
npm ci
npm run check
npm run typecheck
npm run lint
npm run format
npm test
npm run build
```

The generated `.astro/`, `dist/`, and `node_modules/` directories are ignored.
Vite `8.3.4` is pinned because it is a direct config/test dependency and keeps
the validated Astro/React build graph reproducible.

## Development

```sh
npm run dev
```

Run FastAPI on `http://127.0.0.1:8000`. During development, Astro proxies
same-origin `/api` requests to that address. Override the server-only
`API_PROXY_TARGET` when necessary. `PUBLIC_API_BASE_URL` is intended only for a
deployment whose FastAPI server explicitly permits the browser origin.
