# FE-01.1 acceptance

## Recovery cause

The FE-01 documentation was committed while `apps/web` remained a separate,
untracked nested Git worktree. The API foundation also contained malformed
template literals, and the host Node.js 22.23.1 runtime was below requirements
declared by locked Astro packages.

## Corrections

- Preserved the nested Git metadata outside the repository and made
  `apps/web` a normal parent-repository directory.
- Corrected `src/lib/api.ts` and `src/env.d.ts` without invoking the API.
- Retained the real Node.js requirement of `>=22.23.4`.
- Added Astro, TypeScript, ESLint, Prettier, Vitest, and production-build
  scripts.
- Added focused tests for uploader validation, removal, drag/drop, keyboard
  access, placeholder states, and absence of HTTP requests.
- Kept dependencies and generated output out of the staging inventory.

## Reproduction

Run from `apps/web` with Node.js 22.23.4 or newer:

```sh
npm ci
npm run check
npm run typecheck
npm run lint
npm run format
npm test
npm run build
```

## Boundary

FE-01 remains a single-page placeholder experience. It does not perform file
analysis, contact FastAPI, persist files, or claim a security verdict. FE-02 is
not authorized until this recovered source is committed and can be reproduced
from a clean parent-repository checkout.
