# FE-02 acceptance

## Implemented

- Explicit Analyze File action; selection alone sends nothing.
- One multipart request to the existing unified static-analysis endpoint.
- Strict runtime response validation and controlled errors.
- Timeout, cancellation, retry, file replacement, and stale-result rejection.
- Real filename, size, backend-detected format, browser MIME, filename
  extension, format consistency, SHA-256, entropy, string summary, informational
  indicator descriptions, and backend limitations.
- Copyable SHA-256 and accessible status/error announcements.
- Same-origin local development proxy without changing FastAPI CORS policy.
- No persistence, preview, file execution, third-party upload, threat score, or
  security verdict.

## Contract decision

FE-02 uses only `POST /api/v1/static-analyses/`. Separate validation and
fingerprint calls would upload and process the same sample redundantly because
the unified endpoint already performs those operations.

## Verification

The frontend quality gate is:

```powershell
npm run check
npm run typecheck
npm run lint
npm run format
npm test
npm run build
```

The test suite mocks HTTP and does not require an external service. Backend
contract behavior is independently covered by the existing static-analysis
tests. Generated `.astro`, `dist`, and `node_modules` content remains ignored.

Verified results on 2026-10-27 (America/Managua):

- Astro check: 0 errors, 0 warnings, 0 hints.
- TypeScript, ESLint, and Prettier: pass.
- Vitest: 4 files, 24 tests passed.
- Production build: 1 static page built.
- Existing backend upload/fingerprint/static suites: 103 tests passed.
- Live local smoke test: Astro `/api` proxy returned a completed static report
  from FastAPI for `public/favicon.svg`; the SHA-256 length was 64 and all seven
  backend limitations were present.

## Limitations

- The 10 MiB client limit matches the current backend default; a deployment can
  configure a smaller backend limit and return 413.
- The browser cancellation signal does not guarantee immediate backend worker
  cancellation.
- Production cross-origin deployment requires an explicit CORS decision outside
  FE-02; the development proxy is local-only.
- No malware, safety, exploit, CVE, or ATT&CK conclusion is produced.

## Working-tree warning

FE-01 and FE-02 frontend files remain untracked together in the parent
repository until the maintainer performs the documented selective Git handoff.
Parallel Phase 06.07 backend and scenario-document changes are outside this
checkpoint and must remain separate.
