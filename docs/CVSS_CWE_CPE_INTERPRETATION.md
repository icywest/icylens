# CVSS, CWE, and CPE Interpretation

Checkpoint 04.02 adds a transport-independent interpretation layer over the
canonical `VulnerabilityRecord`. CVE identifies a published vulnerability,
CVSS describes technical severity, CWE classifies a weakness, and CPE expresses
product/platform applicability. None proves that an asset is vulnerable,
exploited, compromised, or contains malware.

## CVSS policy

All source metrics and their version, source, type, score, explicit severity,
vector, exploitability score, and impact score are retained. Missing values stay
missing; scores are never recalculated. A separate derived severity is emitted
only from the source base score:

- CVSS 2.0: Low 0.0–3.9, Medium 4.0–6.9, High 7.0–10.0.
- CVSS 3.0, 3.1, and 4.0: None 0.0, Low 0.1–3.9, Medium 4.0–6.9,
  High 7.0–8.9, Critical 9.0–10.0.

The derived label never replaces the published label. Their relationship is
`consistent`, `inconsistent`, or `not_assessable`. These boundaries follow the
[FIRST CVSS v2 guide](https://www.first.org/cvss/v2/guide),
[v3.1 specification](https://www.first.org/cvss/v3-1/specification-document),
and [v4.0 specification](https://www.first.org/cvss/v4-0/specification-document).

The display selection policy is versioned as
`nvd-primary-fixed-version-precedence-v1`:

1. consider scored NVD primary metrics;
2. otherwise consider scored primary metrics from other sources;
3. within a tier use the explicit order 4.0, 3.1, 3.0, 2.0;
4. select only a unique candidate at that tier;
5. if no primary exists, select only when exactly one scored metric exists.

Ties are `ambiguous`; absence of a score is `unavailable`. This fixed display
policy is not numeric version sorting and does not create an operational risk
score. All non-selected metrics remain available with provenance.

## CWE policy

`CWE-NNN` values are `classified`. `NVD-CWE-noinfo` is `not_provided`,
`NVD-CWE-Other` is `other_or_unspecified`, and every other value is
`unrecognized`. Original identifier, description, language, source, and NVD
weakness type are retained. No CWE names, MITRE ATT&CK mappings, or catalog data
are invented or downloaded.

## CPE boundary

The parser accepts CPE 2.3 formatted strings with all eleven components and
understands escaped separators plus the `*` (ANY) and `-` (NA) logical values.
It follows the component layout in [NISTIR 7695](https://doi.org/10.6028/NIST.IR.7695)
and matching concepts in [NISTIR 7696](https://doi.org/10.6028/NIST.IR.7696).
Embedded wildcard patterns, non-2.3 bindings, malformed escapes, and syntax
outside the implemented subset are explicitly unsupported. The implementation
does not claim complete CPE 2.3 conformance.

See [CPE_APPLICABILITY_ENGINE.md](CPE_APPLICABILITY_ENGINE.md) for inventory,
version, logic, evidence, and resource-limit semantics.
