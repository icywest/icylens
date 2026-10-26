# Phase 04 / Checkpoint 04.02 Acceptance

Decision: **PASS**. No source-control operation was performed.

## Delivered controls

- transport-independent CVSS, CWE, CPE, and applicability modules;
- lossless multi-source CVSS interpretation with explicit display selection;
- CWE special-value classification without external enrichment;
- strict declared inventory and structured CPE 2.3 safe-subset parser;
- numeric/SemVer range comparison and four exact NVD bounds;
- explicit TRUE/FALSE/UNKNOWN tables, recursion, negation, multiple roots, and
  required-platform handling;
- auditable condition lists and recursive evaluation tree;
- interpretation GET and applicability POST while preserving the base GET;
- pre-JSON raw-body limit plus product, string, depth, node, condition, and time
  limits;
- sanitized errors and unchanged hardened NVD transport.

## Semantic acceptance

Unsupported syntax cannot silently become `potentially_applicable`, an unknown
version cannot produce a positive range match, and absence from an incomplete
inventory is not negative evidence. Applicability means only that declared
evidence satisfies the interpreted source criteria.

## Validation evidence

On 2026-10-25, `scripts/quality_gate.py` passed with 503 tests, 93.64% combined
statement/branch coverage, Ruff lint PASS, Ruff format PASS, mypy strict PASS
across 77 source files, and `pip check` PASS. `git diff --check` also passed apart
from informational Git line-ending conversion notices. Tests are offline and
deterministic; no live NVD call was required for acceptance.

## Known limits

This is a documented safe subset rather than full CPE 2.3 name matching. It does
not order vendor versions or dates, expand aliases, discover inventory, validate
inventory trust, calculate CVSS, infer ATT&CK, query KEV/EPSS, or calculate risk.
