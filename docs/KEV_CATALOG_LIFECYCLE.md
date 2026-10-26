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
candidates never replace the last valid snapshot.

## Concurrency and ownership

Refresh is service-owned. `KEVCatalogStore` registers at most one active refresh
task. Concurrent consumers share that task through `asyncio.shield()`, so
cancelling one consumer does not cancel the catalog operation or affect another
consumer. The store supervises the task through completion and consumes its
terminal result even if every consumer has departed.

`_refresh_lock` protects only short state transitions: selecting or registering
the active task, authorizing and atomically promoting a validated candidate,
retiring the task, and marking shutdown. It is not held during HTTP, streaming,
retry backoff, JSON parsing, snapshot construction, task waits, or shutdown
drain. Lookups read the last immutable snapshot directly and never wait for a
refresh or initiate provider I/O.

Publication requires the current asyncio task to be the exact registered task,
the task to have no pending cancellation, and the store to remain open. These
checks and the snapshot assignment occur under the same lock without an
intervening suspension. Cleanup also uses task identity, so an older task cannot
clear or publish over a successor.

## Shutdown

`KEVCatalogStore.aclose()` marks the store closed, retires and cancels its active
task under the coordination lock, then releases the lock before awaiting task
collection. New refreshes are rejected and no candidate can be promoted after
shutdown begins. Application lifespan closes the store before closing the CISA
HTTP client.

Cancellation is cooperative. A provider coroutine that suppresses cancellation
temporarily is still denied publication and is collected when it returns. A
coroutine that suppresses cancellation indefinitely cannot be forcibly stopped
by asyncio and can delay shutdown indefinitely.

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
