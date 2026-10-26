# KEV Catalog Lifecycle

## Refresh and promotion

`KEVCatalogStore` owns at most one immutable in-memory snapshot. Refresh is an
internal lifecycle operation; there is no public refresh endpoint. Startup
refresh is opt-in through `ICYLENS_KEV_REFRESH_ON_STARTUP=false` by default.
When enabled it is bounded by the client deadline, and failure never prevents
Health, NVD, static analysis, or ML startup.

A candidate is promoted only after all of these checks complete:

1. bounded decoded download and valid JSON;
2. valid provider envelope and required fields;
3. catalog version and timezone-aware release timestamp;
4. declared count equals the entry array length;
5. entry count is within the configured maximum;
6. valid CVE IDs and record dates;
7. no duplicate CVE IDs;
8. due date is not before date added;
9. release time is not in the future;
10. no conflict with active version/digest and no release rollback.

Promotion is a single reference assignment after construction of a frozen
snapshot with a read-only mapping. Failed, corrupt, conflicting, or older
candidates never replace the last valid snapshot. Concurrent refreshes coalesce
after the first successful promotion.

The SHA-256 digest identifies downloaded content for integrity comparison. It is
not a digital signature and does not independently authenticate CISA; transport
authenticity depends on HTTPS and the fixed endpoint.

## Freshness

Freshness is based on UTC time since successful retrieval:

- `fresh`: age is at most `ICYLENS_KEV_FRESHNESS_SECONDS` (36 hours default);
- `stale`: a snapshot exists but exceeds that age;
- `never_loaded`: no refresh has been attempted;
- `unavailable`: refresh was attempted but no valid snapshot exists.

Stale snapshots remain available because a positive historical listing remains
useful evidence. Their staleness is explicit. Negative lookup against stale data
is `not_established`, never `not_listed`.

## Configuration

| Setting | Default |
|---|---:|
| `KEV_REFRESH_ON_STARTUP` | `false` |
| `KEV_TIMEOUT_SECONDS` | `15` |
| `KEV_TOTAL_DEADLINE_SECONDS` | `60` |
| `KEV_MAX_RESPONSE_BYTES` | `8388608` |
| `KEV_MAX_ENTRIES` | `5000` |
| `KEV_MAX_CONCURRENCY` | `1` |
| `KEV_MAX_RETRIES` | `2` |
| `KEV_BACKOFF_SECONDS` | `0.5` |
| `KEV_MAX_RETRY_AFTER_SECONDS` | `10` |
| `KEV_FRESHNESS_SECONDS` | `129600` |

These are per-process controls, not distributed rate limits. No disk cache or
unexpected persistence exists. Offline tests inject synthetic, explicitly
non-live catalogs and never require network access.
