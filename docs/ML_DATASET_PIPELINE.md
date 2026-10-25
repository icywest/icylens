# ML Dataset Pipeline

## Scope

The Phase 03.02 pipeline turns structured ML records into a deterministic local
dataset artifact. It validates metadata only: it does not parse or retain sample
binaries, download data, infer labels, train models, fit preprocessing, or call
FastAPI. Feature schema `1.0.0` remains unchanged.

```text
bounded UTF-8 JSON/JSONL
  -> strict MLDatasetRecord validation
  -> provenance and label eligibility
  -> deterministic SHA-256 deduplication/conflict rejection
  -> structured validation report
  -> deterministic label-stratified split planning
  -> typed manifest + canonical integrity digest
  -> atomic local artifact export
```

Structurally valid, governance eligible, supervised-training eligible, and
split-assigned are distinct states. Exclusions remain visible in the report.
Fatal findings prevent a build.

## Canonical import formats and bounds

`.json` contains one top-level array of record objects. `.jsonl` contains one
record object per nonblank line and is the canonical artifact format. Both use
strict UTF-8 and ordinary JSON; pickle and arbitrary object deserialization are
not supported.

Default limits are 10 MiB per input, 10,000 records, and 1 MiB per JSONL line.
The JSON reader performs a bounded read. The JSONL reader uses bounded
`readline`, tracks total bytes and record count, and never downloads content.
Empty input, blank lines, invalid UTF-8/JSON, scalar records, unsupported
extensions, oversized content, and excess records are rejected with codes.

JSON is suitable for small reviewed fixtures. JSONL supports bounded sequential
reading for larger local metadata collections. Parquet may be added only when
columnar scale provides a demonstrated benefit and its dependency/security
cost has been reviewed.

## Assessment and deduplication

Strict Pydantic parsing rejects unknown fields, unsupported feature versions,
invalid hashes, missing provenance, invalid labels, and invalid feature values.
Unknown provenance is a fatal governance error. `unknown` labels and otherwise
ineligible labels remain reported but do not enter supervised partitions.

SHA-256 is the exact-content grouping key. For compatible duplicates the
canonical representative is selected by an assigned split first and then the
lexically smallest record ID, independent of input order. Every discarded copy
has an `exact_duplicate` exclusion. A group is fatal when it has different:

- label values or label metadata;
- provenance;
- features or extraction settings; or
- non-`unassigned` split assignments.

No first-record-wins policy is used. SHA-256 does not detect repacking,
recompilation, family relationships, or near duplicates.

## Deterministic splitting

`sha256-stratified-v1` uses the default proposal 70% training, 15% validation,
and 15% test, seed 42, label stratification, exact-SHA grouping, and at least
one sample of each label in every split. Configuration is typed and serialized
in the manifest.

For each label, target counts use largest remainders with stable split-order
ties. Minimum constraints rebalance targets when feasible. Unassigned records
are ranked by SHA-256 of `seed:sample_sha256`, with sample SHA-256 as a stable
secondary key; Python's process-randomized `hash()` and set iteration never
control assignments. Input permutation therefore has no effect.

Existing assignments are immutable. Unassigned records fill the largest target
deficit. A forced distribution deviation produces a warning; assignments that
make minimum class coverage impossible produce a fatal error. Tiny datasets,
single-class datasets, unknown labels, duplicate hashes, and infeasible minimum
constraints are rejected rather than presented as stratified.

The record contract has no reliable family/campaign/near-duplicate group ID,
so the grouping policy truthfully remains `sha256_exact_only`. Future real data
must add verified grouping metadata before claiming family-safe evaluation.
The test split is a sealed future evaluation input and must not participate in
model selection, feature selection, encoding decisions, normalization fitting,
or hyperparameter tuning.

## Manifest and integrity

Manifest schema `1.0.0` records dataset ID/version, feature and builder versions,
represented extraction versions, record/label/split counts, source dataset IDs,
validation summary, complete split configuration, SHA-256 content digest, and
UTC creation metadata. Dataset IDs and versions allow only bounded safe path
components.

`sha256-canonical-json-v1` hashes compact UTF-8 JSON with sorted keys containing:

- canonicalization identifier;
- dataset ID and version;
- builder and feature schema versions;
- complete split configuration; and
- complete released records sorted by sample SHA-256.

The digest field itself and `created_at` are excluded. Therefore identical
content/configuration has the same digest across build times. Counts, labels,
splits, source IDs, extraction versions, feature versions, validation summary,
and record count are revalidated while loading. The digest detects accidental
or unauthorized modification when the manifest digest is trusted; it is not a
digital signature and cannot establish publisher identity against an attacker
who can replace the artifact and digest together.

## Artifacts and persistence

The recommended root is:

```text
datasets/generated/<dataset-id>/<dataset-version>/
  records.jsonl
  manifest.json
  validation_report.json
```

Generated datasets are ignored by Git. Export creates a staging directory in
the target dataset directory, writes all three UTF-8 files, and atomically
renames the directory. Existing versions are never overwritten. Failed writes
remove staging content. This explicitly authorized persistence stores dataset
records and metadata, never uploaded sample binaries.

## CLI

From `apps/api`:

```powershell
.\.venv\Scripts\python.exe scripts\dataset_cli.py validate input.json
.\.venv\Scripts\python.exe scripts\dataset_cli.py build input.json ..\..\datasets\generated --dataset-id lesson-set --dataset-version 1.0.0 --seed 42
.\.venv\Scripts\python.exe scripts\dataset_cli.py inspect ..\..\datasets\generated\lesson-set\1.0.0
```

`validate` writes no artifact and includes split feasibility. `build` fails on
fatal findings or an existing destination. `inspect` validates typed files,
derived counts, report/manifest consistency, and digest. Failures return exit
code 2 with a concise JSON issue code.

## Security and limitations

Implemented controls include byte/record/line limits, strict UTF-8 and schemas,
safe path components, non-overwrite, staged cleanup, deterministic behavior,
no network access, no executable deserialization, no sample bytes, and no raw
content in manifests. Generated artifact access must still follow filesystem
permissions because provenance can be confidential.

Schema validation cannot detect deliberately poisoned but plausible labels,
prove licensing claims, identify all near duplicates, or establish that a
dataset represents real malware. Human/source verification, access controls,
family/temporal contamination analysis, and signed release custody remain
necessary before real training.

## Future training interface

Checkpoint 03.03 may load a verified artifact, use only `training` records to
fit encoders/models, use `validation` for selection, and open `test` once for
final comparison. It must verify the manifest first and preserve feature order
`1.0.0`. This pipeline's ability to produce an artifact is not evidence of
detection quality.
