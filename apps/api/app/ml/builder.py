import hashlib
import json
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError

from app.ml.datasets import is_supervised_training_eligible
from app.ml.splitting import ASSIGNED_SPLITS, SplitPlanningError, plan_splits
from app.schemas.ml_dataset import MLDatasetRecord
from app.schemas.ml_features import FEATURE_SCHEMA_VERSION
from app.schemas.ml_manifest import (
    BUILDER_VERSION,
    DatasetManifest,
    ManifestValidationSummary,
    SplitConfiguration,
)


class BuildIssue(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str
    message: str
    record_ids: tuple[str, ...] = ()
    sha256_values: tuple[str, ...] = ()


class RecordExclusion(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    input_index: int
    code: str
    message: str
    record_id: str | None = None
    sha256: str | None = None


class BuildValidationReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    input_count: int
    structurally_valid_count: int
    governance_eligible_count: int
    training_eligible_count: int
    accepted_count: int
    rejected_count: int
    duplicate_hashes: tuple[str, ...]
    conflicting_label_hashes: tuple[str, ...]
    cross_split_hashes: tuple[str, ...]
    exclusions: tuple[RecordExclusion, ...]
    warnings: tuple[BuildIssue, ...]
    errors: tuple[BuildIssue, ...]
    ready_for_splitting: bool


class DatasetAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    accepted_records: tuple[MLDatasetRecord, ...]
    report: BuildValidationReport


class DatasetBuildResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    records: tuple[MLDatasetRecord, ...]
    manifest: DatasetManifest
    validation_report: BuildValidationReport


class DatasetBuildError(ValueError):
    def __init__(self, code: str, message: str, report: BuildValidationReport) -> None:
        super().__init__(message)
        self.code = code
        self.report = report


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _validation_messages(error: ValidationError) -> str:
    return "; ".join(
        f"{'.'.join(str(part) for part in item['loc'])}: {item['msg']}"
        for item in error.errors()
    )


def _validation_exclusion_code(error: ValidationError) -> str:
    locations = {tuple(item["loc"]) for item in error.errors()}
    if any(
        location[:1] == ("provenance",) and item["type"] == "missing"
        for item in error.errors()
        for location in [tuple(item["loc"])]
    ):
        return "missing_provenance"
    if any(
        location
        in {
            ("features", "feature_schema_version"),
            ("extraction", "feature_schema_version"),
        }
        for location in locations
    ):
        return "unsupported_feature_schema_version"
    if any(location[:1] == ("label",) for location in locations):
        return "invalid_label"
    return "invalid_record"


def _record_issue(
    code: str,
    message: str,
    records: Sequence[tuple[int, MLDatasetRecord]],
) -> BuildIssue:
    return BuildIssue(
        code=code,
        message=message,
        record_ids=tuple(sorted(record.identity.record_id for _, record in records)),
        sha256_values=tuple(sorted({record.identity.sha256 for _, record in records})),
    )


def assess_dataset(
    candidates: Sequence[MLDatasetRecord | Mapping[str, Any]],
) -> DatasetAssessment:
    parsed: list[tuple[int, MLDatasetRecord]] = []
    exclusions: list[RecordExclusion] = []
    warnings: list[BuildIssue] = []
    errors: list[BuildIssue] = []
    for index, candidate in enumerate(candidates):
        try:
            record = MLDatasetRecord.model_validate(candidate)
        except ValidationError as error:
            exclusions.append(
                RecordExclusion(
                    input_index=index,
                    code=_validation_exclusion_code(error),
                    message=_validation_messages(error),
                )
            )
        else:
            parsed.append((index, record))

    if exclusions:
        errors.append(
            BuildIssue(
                code="structural_validation_failed",
                message="One or more input records failed strict schema validation.",
            )
        )

    by_record_id: dict[str, list[tuple[int, MLDatasetRecord]]] = defaultdict(list)
    by_hash: dict[str, list[tuple[int, MLDatasetRecord]]] = defaultdict(list)
    for indexed in parsed:
        _, record = indexed
        by_record_id[record.identity.record_id].append(indexed)
        by_hash[record.identity.sha256].append(indexed)
    for records in by_record_id.values():
        hashes = {record.identity.sha256 for _, record in records}
        if len(hashes) > 1:
            errors.append(
                _record_issue(
                    "duplicate_record_id",
                    "A record identifier refers to different SHA-256 identities.",
                    records,
                )
            )

    accepted: list[tuple[int, MLDatasetRecord]] = []
    duplicate_hashes: list[str] = []
    conflicting_labels: list[str] = []
    cross_split_hashes: list[str] = []
    conflict_indexes: set[int] = set()
    for sha256 in sorted(by_hash):
        records = by_hash[sha256]
        if len(records) == 1:
            accepted.append(records[0])
            continue
        duplicate_hashes.append(sha256)
        labels = {record.label.value for _, record in records}
        label_contracts = {
            _canonical_json(record.label.model_dump(mode="json"))
            for _, record in records
        }
        provenances = {
            _canonical_json(record.provenance.model_dump(mode="json"))
            for _, record in records
        }
        feature_contracts = {
            _canonical_json(
                {
                    "features": record.features.model_dump(mode="json"),
                    "extraction": record.extraction.model_dump(mode="json"),
                }
            )
            for _, record in records
        }
        assigned_splits = {
            record.split for _, record in records if record.split != "unassigned"
        }
        conflict_codes: list[tuple[str, str]] = []
        if len(labels) > 1:
            conflicting_labels.append(sha256)
            conflict_codes.append(
                ("conflicting_labels", "Identical content has conflicting labels.")
            )
        elif len(label_contracts) > 1:
            conflict_codes.append(
                (
                    "conflicting_label_metadata",
                    "Identical content has conflicting label metadata.",
                )
            )
        if len(provenances) > 1:
            conflict_codes.append(
                (
                    "conflicting_provenance",
                    "Identical content has conflicting provenance.",
                )
            )
        if len(feature_contracts) > 1:
            conflict_codes.append(
                (
                    "conflicting_record_content",
                    "Identical content has conflicting features or extraction settings.",
                )
            )
        if len(assigned_splits) > 1:
            cross_split_hashes.append(sha256)
            conflict_codes.append(
                (
                    "cross_split_duplicate",
                    "Identical content has conflicting split assignments.",
                )
            )
        if conflict_codes:
            conflict_indexes.update(index for index, _ in records)
            for code, message in conflict_codes:
                errors.append(_record_issue(code, message, records))
            continue

        canonical = min(
            records,
            key=lambda item: (
                item[1].split == "unassigned",
                item[1].identity.record_id,
                _canonical_json(item[1].model_dump(mode="json")),
            ),
        )
        accepted.append(canonical)
        for index, record in records:
            if index == canonical[0]:
                continue
            exclusions.append(
                RecordExclusion(
                    input_index=index,
                    code="exact_duplicate",
                    message="Excluded deterministic duplicate of identical content.",
                    record_id=record.identity.record_id,
                    sha256=sha256,
                )
            )
        warnings.append(
            _record_issue(
                "exact_duplicate_excluded",
                "One canonical record was retained for identical content.",
                records,
            )
        )

    for index, record in parsed:
        if index in conflict_indexes:
            exclusions.append(
                RecordExclusion(
                    input_index=index,
                    code="hash_conflict",
                    message="Excluded because identical content has conflicting metadata.",
                    record_id=record.identity.record_id,
                    sha256=record.identity.sha256,
                )
            )

    governance_eligible = [
        (index, record)
        for index, record in accepted
        if record.provenance.source_kind != "unknown"
    ]
    for index, record in accepted:
        if record.provenance.source_kind == "unknown":
            exclusions.append(
                RecordExclusion(
                    input_index=index,
                    code="unsupported_provenance",
                    message="Unknown provenance is not accepted.",
                    record_id=record.identity.record_id,
                    sha256=record.identity.sha256,
                )
            )
            errors.append(
                _record_issue(
                    "unsupported_provenance",
                    "Unknown provenance fails dataset governance.",
                    [(index, record)],
                )
            )

    training_eligible = [
        (index, record)
        for index, record in governance_eligible
        if is_supervised_training_eligible(record)
    ]
    eligible_indexes = {index for index, _ in training_eligible}
    for index, record in governance_eligible:
        if index in eligible_indexes:
            continue
        code = (
            "unknown_label_excluded"
            if record.label.value == "unknown"
            else "not_training_eligible"
        )
        exclusions.append(
            RecordExclusion(
                input_index=index,
                code=code,
                message="Record is not eligible for supervised training.",
                record_id=record.identity.record_id,
                sha256=record.identity.sha256,
            )
        )
        warnings.append(
            _record_issue(
                code,
                "Record remains visible but is excluded from supervised partitions.",
                [(index, record)],
            )
        )

    accepted_records = tuple(
        record
        for _, record in sorted(
            training_eligible, key=lambda item: item[1].identity.sha256
        )
    )
    report = BuildValidationReport(
        input_count=len(candidates),
        structurally_valid_count=len(parsed),
        governance_eligible_count=len(governance_eligible),
        training_eligible_count=len(training_eligible),
        accepted_count=len(accepted_records),
        rejected_count=len(candidates) - len(accepted_records),
        duplicate_hashes=tuple(duplicate_hashes),
        conflicting_label_hashes=tuple(conflicting_labels),
        cross_split_hashes=tuple(cross_split_hashes),
        exclusions=tuple(sorted(exclusions, key=lambda item: item.input_index)),
        warnings=tuple(warnings),
        errors=tuple(errors),
        ready_for_splitting=not errors and bool(accepted_records),
    )
    return DatasetAssessment(accepted_records=accepted_records, report=report)


def _digest_payload(
    dataset_id: str,
    dataset_version: str,
    records: Sequence[MLDatasetRecord],
    split_configuration: SplitConfiguration,
) -> dict[str, object]:
    return {
        "builder_version": BUILDER_VERSION,
        "canonicalization": "utf8-json-sort-keys-compact-v1",
        "dataset_id": dataset_id,
        "dataset_version": dataset_version,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "records": [
            record.model_dump(mode="json")
            for record in sorted(records, key=lambda item: item.identity.sha256)
        ],
        "split_configuration": split_configuration.model_dump(mode="json"),
    }


def compute_dataset_digest(
    dataset_id: str,
    dataset_version: str,
    records: Sequence[MLDatasetRecord],
    split_configuration: SplitConfiguration,
) -> str:
    payload = _canonical_json(
        _digest_payload(dataset_id, dataset_version, records, split_configuration)
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def summarize_validation_report(
    report: BuildValidationReport,
) -> ManifestValidationSummary:
    codes = Counter(issue.code for issue in (*report.warnings, *report.errors))
    codes.update(exclusion.code for exclusion in report.exclusions)
    return ManifestValidationSummary(
        input_count=report.input_count,
        structurally_valid_count=report.structurally_valid_count,
        governance_eligible_count=report.governance_eligible_count,
        training_eligible_count=report.training_eligible_count,
        accepted_count=report.accepted_count,
        excluded_count=report.rejected_count,
        warning_count=len(report.warnings),
        error_count=len(report.errors),
        issue_code_counts=dict(sorted(codes.items())),
        ready_for_training=not report.errors and report.accepted_count > 0,
    )


def build_dataset(
    candidates: Sequence[MLDatasetRecord | Mapping[str, Any]],
    *,
    dataset_id: str,
    dataset_version: str,
    split_configuration: SplitConfiguration | None = None,
    created_at: datetime | None = None,
) -> DatasetBuildResult:
    split_configuration = split_configuration or SplitConfiguration()
    assessment = assess_dataset(candidates)
    if not assessment.report.ready_for_splitting:
        raise DatasetBuildError(
            "dataset_not_ready",
            "dataset validation produced fatal findings",
            assessment.report,
        )
    try:
        split_plan = plan_splits(assessment.accepted_records, split_configuration)
    except SplitPlanningError as error:
        failed_report = assessment.report.model_copy(
            update={
                "errors": (
                    *assessment.report.errors,
                    BuildIssue(code=error.code, message=str(error)),
                ),
                "ready_for_splitting": False,
            }
        )
        raise DatasetBuildError(error.code, str(error), failed_report) from error

    split_warnings = tuple(
        BuildIssue(
            code=warning.partition(":")[0],
            message=warning,
        )
        for warning in split_plan.warnings
    )
    final_report = assessment.report.model_copy(
        update={"warnings": (*assessment.report.warnings, *split_warnings)}
    )
    timestamp = created_at or datetime.now(UTC)
    label_counts = Counter(record.label.value for record in split_plan.records)
    extraction_versions = tuple(
        sorted({record.extraction.extractor_version for record in split_plan.records})
    )
    source_identifiers = tuple(
        sorted({record.provenance.dataset_id for record in split_plan.records})
    )
    digest = compute_dataset_digest(
        dataset_id,
        dataset_version,
        split_plan.records,
        split_configuration,
    )
    manifest = DatasetManifest(
        dataset_id=dataset_id,
        dataset_version=dataset_version,
        extraction_versions=extraction_versions,
        record_count=len(split_plan.records),
        eligible_record_count=len(split_plan.records),
        excluded_record_count=final_report.rejected_count,
        label_counts=dict(sorted(label_counts.items())),
        split_counts=split_plan.split_counts,
        source_identifiers=source_identifiers,
        validation_summary=summarize_validation_report(final_report),
        split_configuration=split_configuration,
        content_integrity_digest=digest,
        created_at=timestamp,
    )
    return DatasetBuildResult(
        records=split_plan.records,
        manifest=manifest,
        validation_report=final_report,
    )


def verify_dataset_integrity(
    manifest: DatasetManifest,
    records: Sequence[MLDatasetRecord],
) -> bool:
    if manifest.record_count != len(records):
        return False
    label_counts = Counter(record.label.value for record in records)
    split_counts = Counter(record.split for record in records)
    if manifest.label_counts != dict(sorted(label_counts.items())):
        return False
    expected_splits = {split: split_counts[split] for split in ASSIGNED_SPLITS}
    if manifest.split_counts != expected_splits:
        return False
    if manifest.extraction_versions != tuple(
        sorted({record.extraction.extractor_version for record in records})
    ):
        return False
    if manifest.source_identifiers != tuple(
        sorted({record.provenance.dataset_id for record in records})
    ):
        return False
    if any(
        record.features.feature_schema_version != manifest.feature_schema_version
        for record in records
    ):
        return False
    actual = compute_dataset_digest(
        manifest.dataset_id,
        manifest.dataset_version,
        records,
        manifest.split_configuration,
    )
    return actual == manifest.content_integrity_digest
