# Frontend file analysis integration

## Scope

FE-02 implements one local, ephemeral flow:

```text
browser File -> local checks -> multipart POST -> FastAPI static analysis
  -> strict runtime validation -> technical results -> limitations
```

The browser does not execute, parse, persist, preview, hash, or upload the file
to a third party. Selecting a file does not start a request.

## Contract inventory

| Operation | Endpoint | Request | Response | FE-02 |
|---|---|---|---|---|
| Health | `GET /api/v1/health/` | None | status, service, version, message | Not called |
| Upload validation | `POST /api/v1/uploads/` | multipart field `file` | upload ID, filename, size, declared content type, validated status, persisted=false | Not called; redundant |
| Fingerprint | `POST /api/v1/fingerprints/` | multipart field `file` | filename, SHA-256, size, detected format, signature metadata, extension consistency | Not called; unified result includes required fields |
| Static analysis | `POST /api/v1/static-analyses/` | multipart field `file` | strict static report | Yes |

The static endpoint performs its own upload validation and returns SHA-256,
size, detected format, extension consistency, Shannon entropy, bounded string
counts, informational indicators, truncation state, timestamps, and explicit
analysis limitations. A successful response has `analysis_type=static` and
`status=completed`.

The configured default maximum is 10 MiB (`10485760` bytes). The backend reads
in bounded chunks and rejects empty content or invalid filenames with 422 and
oversized input with 413. Unexpected static-analysis failures return a generic
500 response. There is no extension allowlist. Format detection can return
`pdf`, `png`, `jpeg`, `gif`, `zip`, `pe`, `elf`, or `unknown`.

No route-specific backend processing timeout or concurrency limit is defined
for this endpoint. The frontend applies a 30-second request timeout. Aborting
`fetch` stops the browser request but does not promise immediate cancellation of
backend processing.

## Runtime validation

`src/lib/api.ts` validates the complete response with strict Zod schemas. It
rejects unknown fields, missing fields, invalid UUIDs, non-UTC timestamps,
invalid SHA-256 values, out-of-range entropy, raw-string exposure, inconsistent
byte counts, and reversed timestamps. Invalid JSON or incompatible data never
reaches the results UI.

## Request lifecycle

React owns one `AbortController` per analysis. Selecting, removing, or replacing
a file invalidates the request sequence and aborts the active request. Results
are committed only when their sequence still matches the current file. The user
can cancel or retry, and no previous result is retained for a new file.

## Local connectivity

The FastAPI application currently installs no CORS middleware. Astro therefore
proxies `/api` during local development:

```text
browser http://localhost:4321/api/... -> Vite proxy -> http://127.0.0.1:8000/api/...
```

`API_PROXY_TARGET` changes only the development proxy target and is not exposed
to browser code. `PUBLIC_API_BASE_URL` may select another browser-visible base
URL, but that deployment must explicitly permit the frontend origin. FE-02 does
not weaken FastAPI CORS policy.

## Run locally

Backend, from `apps/api`:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Frontend, from `apps/web`, with Node.js 22.23.4 or newer:

```powershell
npm ci
npm run dev
```

## Scientific boundary

Detected format is bounded signature evidence, not complete structural
validation. Browser MIME is client-declared metadata. Entropy describes byte
distribution. Text indicators are informational and may be benign. SHA-256
identifies content deterministically. None of these fields establishes safety,
malware, exploitation, a CVE relationship, or ATT&CK execution.
