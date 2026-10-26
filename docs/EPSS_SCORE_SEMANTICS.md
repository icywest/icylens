# EPSS score semantics

EPSS is FIRST's statistical estimate that a published CVE will be exploited in
the wild during the next 30 days. A score of `0.100000` is approximately a 10%
estimated probability within that EPSS horizon. It is not CVSS severity,
evidence of active exploitation, proof of asset compromise, malware evidence,
or the probability that a particular device will be compromised.

The percentile is ranking context, not a second exploitation probability. A
percentile of `0.950000` means the score is at or above roughly 95% of scored
vulnerabilities; it must not be described as a 95% probability of attack.
This checkpoint neither combines score and percentile nor constructs a risk
score.

Scores and percentiles are parsed as exact `Decimal` values and serialized as
JSON strings. This preserves the precision and trailing zeros published by
FIRST. Both values must be finite and within zero through one inclusive. Zero
is a valid score; absence is represented with `null` and `not_scored`.

`score_date` is FIRST's date for the published score. `retrieved_at` is the UTC
instant iCYLENS fetched it. They are never substituted for one another. A
future score date is rejected. Freshness is computed from UTC calendar dates:

- `current`: age 0–1 days by default, tolerating normal daily publication lag;
- `stale`: age 2–7 days by default;
- `historical`: older than 7 days;
- `unavailable`: no score date exists.

The thresholds are configurable and stale data is never relabeled current on
a cache hit. Historical data may still be useful as dated evidence but must
not be presented as the current estimate.

The envelope's `version` is recorded as `api_version`. It is not an EPSS model
version. Because the point API does not provide independently verifiable model
generation metadata, `model_version` is `null`. Scores produced by different
model generations may not be directly comparable; no generation is inferred
from a date.

Use EPSS alongside asset presence, exposure, business impact, CVSS, KEV, and
other evidence while keeping each source's meaning distinct. See FIRST's
[EPSS overview](https://www.first.org/epss/) and
[data documentation](https://www.first.org/epss/data.html).

