# ML Dataset Governance

## Purpose and authority

This policy governs data considered for iCYLENS supervised machine learning.
It covers acquisition approval, provenance, labels, versioning, validation,
splitting, privacy, licensing, and safe handling. The committed dataset is a
small, deterministic, non-executable synthetic test fixture only. It is not a
training corpus and makes no detection-performance claim.

## Acceptable sources and licensing

Data may enter a governed dataset only when its owner, acquisition method,
license, redistribution rights, permitted uses, retention rules, and usage
restrictions are documented and approved. Acceptable source kinds are:

- locally generated synthetic data, explicitly marked synthetic;
- project-owned data collected with authority and a documented purpose;
- licensed data whose ML and redistribution terms are compatible; or
- research data with documented authorization, ethics, and license terms.

Unknown provenance is rejected. Public availability is not proof of a right to
download, retain, redistribute, or use data for ML. No arbitrary file may be
uploaded to a public threat-intelligence service. This checkpoint downloads no
external dataset and contains no executable malware.

## Required provenance

Each record identifies its dataset, source kind and description, collection
date, license, restrictions, extraction adapter version, feature schema
version, and exact extraction bounds. SHA-256 identifies exact bytes but is not
a predictive feature. A manifest for a future real dataset must also record
the dataset release/version, acquisition process, custodian, integrity checks,
and any transformations. Changes create a new immutable dataset version; old
manifests remain reproducible and are not edited in place.

Reproduction requires the same byte identity, code revision, feature schema,
adapter version, extraction configuration, and deterministic build command.
Environment and dependency lock information must accompany a training release.

## Label taxonomy and verification

The initial taxonomy is `benign`, `malicious`, and `unknown`.

- `benign` requires affirmative, documented ground truth appropriate to the
  source and collection time. Absence of a detection is not enough.
- `malicious` requires documented ground truth and verification. A suspicious
  string, entropy value, format mismatch, CVE association, or future MITRE
  technique mapping is not a malware label.
- `unknown` means ground truth is absent or insufficient. It is retained for
  analysis but excluded from supervised training.

Every label has a source, optional confidence/quality value, verification date
when verified, and a synthetic marker. Synthetic scenario labels are never
presented as observed real-world truth. Sources do not have equal authority;
future source-specific verification rules and disagreement adjudication must
be recorded in the dataset manifest. Labels are never inferred automatically
from the current static indicators.

## Deduplication, splitting, and leakage prevention

Dataset validation reports duplicate SHA-256 values, conflicting labels for an
identical hash, duplicate record IDs, and identical hashes crossing assigned
splits. Import leaves records `unassigned`; split assignment is a deliberate,
versioned operation after deduplication and label review.

SHA-256 equality detects exact copies only. It cannot remove repackaged,
recompiled, normalized, templated, family-related, or otherwise near-duplicate
samples. Future builders must evaluate similarity/family grouping, temporal
separation, and source diversity. Repeated synthetic feature templates are
warned because they can inflate an evaluation despite different hashes.

No feature may be derived from the label, label source, dataset source,
filename, split, collection decision, arbitrary identifier, analysis UUID, or
post-outcome knowledge. Strict nested schemas reject such extra fields, but
code and data reviews remain mandatory. Preprocessing statistics and feature
selection are fit on training data only. Validation data supports model and
hyperparameter selection. The independent test set remains sealed until final
evaluation and is never used to tune the model. Cross-split exact and grouped
overlap are release-blocking errors.

Potential contamination must be recorded when a sample, family, campaign,
source feed, time window, or synthetic generator could occur in more than one
split or in external pretraining data. A hash-only check is insufficient.

## Dataset quality

Validation never silently repairs data. It distinguishes schema-invalid
records, valid records, warnings, and dataset-level errors. It rejects missing
mandatory fields, unexpected fields, invalid hashes/categories/labels,
non-finite or out-of-range numbers, incompatible schema versions, and unknown
provenance. It warns when an otherwise valid record is ineligible for
supervised training or repeats a synthetic feature template.

Class distribution, per-source distribution, temporal coverage, missingness,
truncation rates, and label quality must be reported before training. Class
imbalance is handled through explicit evaluation and training choices, never
by deleting difficult cases or fabricating performance. Metrics must be broken
down by relevant source/time/format groups, with limitations reported.

## Privacy, security, and malicious-sample handling

Collect only data necessary for the documented educational purpose. Remove or
quarantine personal data and secrets under an approved process; do not place
raw strings, credentials, private URLs, or personal identifiers in fixtures,
logs, reports, or commits. Apply retention and deletion obligations from the
source license and privacy policy.

Real malicious samples, if approved in a future checkpoint, require isolated
storage, least-privilege access, integrity tracking, encryption, no-execute
controls, network isolation, safe transfer procedures, incident response, and
legal authorization. They must never be executed on developer or CI systems.
Only inert synthetic records are permitted in ordinary automated tests.

## Release checklist

A dataset version cannot be used for supervised training until its manifest,
license review, provenance, label audit, feature/extraction versions,
deduplication results, grouped/temporal split rationale, contamination review,
privacy review, class/source statistics, and sealed-test custody are approved.
Validation errors block release; warnings require a documented disposition.
