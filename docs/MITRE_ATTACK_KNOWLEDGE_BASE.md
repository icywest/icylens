# MITRE ATT&CK knowledge base

Phase 05 checkpoint 05.01 installs one read-only Enterprise ATT&CK catalog. It
is knowledge about documented adversary behavior, not evidence that behavior
occurred on a device.

## Fixed source and local artifact

- Domain: `enterprise-attack` only.
- ATT&CK release: 19.2, released 5 August 2026.
- Official STIX 2.1 source: `attack-stix-data` tag `v19.2`, file
  `enterprise-attack/enterprise-attack-19.2.json`.
- Source URL: <https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v19.2/enterprise-attack/enterprise-attack-19.2.json>
- Acquired: 26 October 2026 (UTC timestamp retained in the snapshot).
- Source SHA-256: `dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4`.
- Raw objects: 26,086; tactics: 15; techniques: 858; sub-techniques: 493;
  relationships: 21,262.
- Active techniques: 697; retired/unknown techniques retained: 161.

The repository commits a deterministic gzip-compressed normalized snapshot at
`apps/api/app/attack/data/enterprise-attack-19.2.json.gz` (about 1.5 MB), not
the roughly 51 MB source bundle. Lookups therefore require no network. The raw
source digest is verified during import and pinned again during local loading.
The digest authenticates byte identity against this project pin; it is not an
independent signature from MITRE.

## Lifecycle and query policy

Revocation and deprecation are separate fields and yield separate states.
Absence of both flags is represented as `unknown`, not silently changed to
false. Historical entries remain in the snapshot for referential integrity,
but public lists and lookups exclude deprecated, revoked, and unknown entries
by default. A caller must pass `include_retired=true` to retrieve them.

ATT&CK 19.2 retains 16 revoked objects marked as sub-techniques after their
historical `subtechnique-of` relationship was removed. Only for those objects,
the importer accepts a parent when the object is explicitly revoked, is marked
as a sub-technique, has an official dotted ATT&CK ID, and the corresponding
parent object exists in the same bundle. Active objects always require the
official relationship.

All relationship endpoints must resolve to an object in the source bundle.
Technique-to-tactic membership is taken from `kill_chain_phases` and resolved
against official tactic short names. It is not invented as a STIX relationship.

ATT&CK data-source and data-component objects are not needed to validate a
technique and are not exposed by this checkpoint. This is deliberate because
MITRE deprecated the legacy ATT&CK Data Sources structure from version 18. A
future behavioral event schema must remain independent of it.

## Deliberate update procedure

The importer uses one fixed HTTPS URL, disables redirects and environment proxy
inheritance, streams with a 64 MiB limit, uses bounded timeouts/retries and a
total deadline, validates JSON/STIX structure, and atomically replaces only its
configured CLI output. It is never called by an HTTP endpoint.

```powershell
Set-Location C:\icylens\apps\api
.\.venv\Scripts\python.exe scripts\import_attack_catalog.py
```

Changing the ATT&CK release requires a reviewed code change to the URL, version,
expected digest, fixture expectations, documentation, and generated snapshot.
The public API cannot choose a version, URL, or output path.

## Scientific boundary

Valid claims include that a technique exists in this snapshot, belongs to a
tactic, has a documented parent, or is retired. Catalog presence does not show
execution, compromise, malware, endpoint observation, or any CVE/CWE mapping.
No Phase 02, Phase 03, or Phase 04 evidence is joined to ATT&CK here.

