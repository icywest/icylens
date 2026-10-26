# Evidence correlation policy

The unified endpoint reports source-backed statements, not a narrative risk
conclusion. Every `EvidenceStatement` identifies its type, source, canonical
CVE, typed scalar value, source timestamp, retrieval timestamp, freshness,
response reference, and limitations.

## Allowed statements

- NVD CVE record available.
- One or more source CVSS metrics present.
- Published CWE information available.
- Declared-inventory CPE applicability evaluated.
- CVE listed in CISA KEV.
- CVE not listed in a fresh verified KEV snapshot.
- Dated EPSS estimate available.
- FIRST returned no EPSS score.

Unavailable, timed-out, rate-limited, or invalid sources create no positive or
negative evidence statement. Their source result carries only a safe error
code and limitation.

## Negative evidence

Negative results are narrowly scoped:

- NVD `not_found` means only that the point query returned no NVD record.
- KEV `not_listed` is emitted only from a fresh verified snapshot and does not
  mean exploitation is impossible.
- A stale KEV negative remains `not_established` and produces no not-listed
  statement.
- EPSS `not_scored` means no estimate was returned and never becomes score
  zero.
- No inventory means applicability is `null`, not `not_applicable`.

Valid EPSS zero remains an available dated estimate. EPSS score precision and
percentile remain decimal strings. Percentile is ranking context, not another
probability. CVSS remains severity; KEV remains published known-exploitation
evidence; neither proves exploitation or compromise inside an organization.

## Time

The response preserves independent clocks: NVD publication/last-modified and
retrieval times, KEV catalog release and snapshot fetch times, EPSS score date
and retrieval time, and unified generation time. A stale KEV positive remains
visible with a stale warning. Stale or historical EPSS retains its original
freshness and is not represented as a current prediction.

## Determinism and identity

All nested evidence, interpretation and applicability must match the requested
CVE. A mismatch becomes invalid source data and cannot contaminate another
source. For identical source facts, evidence statements are semantically
equivalent regardless of source-object key order, correlation UUID, unified
generation time, or changes only to retrieval timestamps.

No statement may claim malware detection, confirmed asset vulnerability,
organizational exploitation, compromise, safety, threat-actor attribution, or
a combined numerical risk.

