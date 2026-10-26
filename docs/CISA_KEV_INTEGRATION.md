# CISA KEV Integration

Checkpoint 04.03 integrates the canonical CISA Known Exploited Vulnerabilities
(KEV) JSON feed as an independent source of published known-exploitation
evidence:

`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

The [CISA catalog page](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
defines the program. The CISA-owned
[`cisagov/kev-data`](https://github.com/cisagov/kev-data) repository is used only
to verify the current JSON schema; it is not a runtime fallback. No HTML scraping
or third-party mirror is used.

## Provider and canonical contracts

The bounded provider envelope accepts `title`, `catalogVersion`, `dateReleased`,
`count`, and `vulnerabilities`. Current record fields include `cveID`,
`vendorProject`, `product`, `vulnerabilityName`, `dateAdded`,
`shortDescription`, `requiredAction`, `dueDate`,
`knownRansomwareCampaignUse`, `forensicTriage`, `notes`, and `cwes`.
Officially optional values remain null when absent, unknown future fields are
ignored at the provider boundary, and bounded unknown textual status values are
preserved.

Canonical `KEVRecord` 1.0.0 uses iCYLENS field names and retains catalog version,
release timestamp, canonical source URL, and CISA provenance. Product text is
not treated as a validated CPE. No CVSS, EPSS, affected version, actor, campaign,
or risk value is invented.

## HTTP policy

The client permits exactly the canonical HTTPS host/path, TLS verification,
disabled redirects, and `trust_env=False`. It uses a single lifespan-owned
`httpx.AsyncClient`, per-phase timeouts, a total deadline, bounded concurrency,
finite jittered retries, and response cleanup in `finally`.

The default decoded-body limit is 8 MiB. `aiter_bytes()` enforces it after HTTP
content decoding, so compressed expansion counts toward the limit. JSON is
fully materialized after the bounded download; constant-memory JSON parsing is
not claimed. JSON depth is limited to 16 and the catalog to 5,000 entries.

## Public API

- `GET /api/v1/intelligence/kev/status` returns only availability, catalog
  version/release, retrieval time, freshness age, and count.
- `GET /api/v1/intelligence/kev/{cve_id}` reads the active in-memory index.

The lookup returns 200 with `listed`, `not_listed`, or `not_established`. A fresh
verified negative is `not_listed`, but explicitly is not proof that exploitation
does not exist. A stale negative is `not_established`. With no validated snapshot
the lookup returns sanitized 503. Neither endpoint initiates refreshes.

`knownRansomwareCampaignUse="Unknown"` means CISA lacks confirmation; it does
not mean no ransomware involvement. `dateAdded`, `dueDate`, and
`requiredAction` are CISA-published references, not universal legal or
organizational compliance determinations.

## Live verification

On 2026-10-25, one controlled canonical fetch validated catalog version
`2026.10.23`, release `2026-10-23T19:30:18.920900Z`, 1,756 unique records, full
parsing, SHA-256 digesting, and in-memory indexing. The catalog was not persisted.
