from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError

from app.ml.datasets import is_supervised_training_eligible
from app.schemas.ml_dataset import MLDatasetRecord


class ValidationIssue(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str
    message: str
    record_indexes: tuple[int, ...] = ()
    record_ids: tuple[str, ...] = ()


class InvalidDatasetRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    index: int
    errors: tuple[str, ...]


class DatasetValidationReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    valid_records: tuple[MLDatasetRecord, ...]
    invalid_records: tuple[InvalidDatasetRecord, ...]
    warnings: tuple[ValidationIssue, ...]
    dataset_errors: tuple[ValidationIssue, ...]

    @property
    def is_valid(self) -> bool:
        return not self.invalid_records and not self.dataset_errors


def _issue(
    code: str,
    message: str,
    indexed_records: Sequence[tuple[int, MLDatasetRecord]],
) -> ValidationIssue:
    return ValidationIssue(
        code=code,
        message=message,
        record_indexes=tuple(index for index, _ in indexed_records),
        record_ids=tuple(record.identity.record_id for _, record in indexed_records),
    )


def _validation_messages(error: ValidationError) -> tuple[str, ...]:
    return tuple(
        f"{'.'.join(str(part) for part in item['loc'])}: {item['msg']}"
        for item in error.errors()
    )


def validate_dataset(
    records: Sequence[MLDatasetRecord | Mapping[str, Any]],
) -> DatasetValidationReport:
    valid: list[tuple[int, MLDatasetRecord]] = []
    invalid: list[InvalidDatasetRecord] = []
    warnings: list[ValidationIssue] = []
    errors: list[ValidationIssue] = []

    for index, candidate in enumerate(records):
        try:
            record = MLDatasetRecord.model_validate(candidate)
        except ValidationError as error:
            invalid.append(
                InvalidDatasetRecord(
                    index=index,
                    errors=_validation_messages(error),
                )
            )
        else:
            valid.append((index, record))

    by_hash: dict[str, list[tuple[int, MLDatasetRecord]]] = defaultdict(list)
    by_record_id: dict[str, list[tuple[int, MLDatasetRecord]]] = defaultdict(list)
    for indexed_record in valid:
        _, record = indexed_record
        by_hash[record.identity.sha256].append(indexed_record)
        by_record_id[record.identity.record_id].append(indexed_record)

        if record.provenance.source_kind == "unknown":
            errors.append(
                _issue(
                    "unsupported_provenance",
                    "Unknown provenance is not accepted for governed datasets.",
                    [indexed_record],
                )
            )
        if record.label.value == "unknown":
            warnings.append(
                _issue(
                    "unknown_label_excluded",
                    "Unknown labels are excluded from supervised training.",
                    [indexed_record],
                )
            )
        elif not is_supervised_training_eligible(record):
            warnings.append(
                _issue(
                    "not_training_eligible",
                    "The record lacks verified or provenance-consistent ground truth.",
                    [indexed_record],
                )
            )

    for indexed_records in by_record_id.values():
        if len(indexed_records) > 1:
            errors.append(
                _issue(
                    "duplicate_record_id",
                    "Record identifiers must be unique.",
                    indexed_records,
                )
            )

    for indexed_records in by_hash.values():
        if len(indexed_records) < 2:
            continue
        errors.append(
            _issue(
                "duplicate_sha256",
                "Identical SHA-256 identities occur more than once.",
                indexed_records,
            )
        )
        labels = {record.label.value for _, record in indexed_records}
        if len(labels) > 1:
            errors.append(
                _issue(
                    "conflicting_labels",
                    "Identical SHA-256 identities have conflicting labels.",
                    indexed_records,
                )
            )
        assigned_splits = {
            record.split
            for _, record in indexed_records
            if record.split != "unassigned"
        }
        if len(assigned_splits) > 1:
            errors.append(
                _issue(
                    "cross_split_duplicate",
                    "Identical SHA-256 identities cross dataset splits.",
                    indexed_records,
                )
            )

    synthetic_templates: dict[
        tuple[int | float | str | bool, ...],
        list[tuple[int, MLDatasetRecord]],
    ] = defaultdict(list)
    for indexed_record in valid:
        _, record = indexed_record
        if record.provenance.source_kind == "synthetic":
            synthetic_templates[record.features.ordered_predictive_values()].append(
                indexed_record
            )
    for indexed_records in synthetic_templates.values():
        hashes = {record.identity.sha256 for _, record in indexed_records}
        if len(hashes) > 1:
            warnings.append(
                _issue(
                    "repeated_synthetic_template",
                    "Different identities share an identical synthetic feature vector.",
                    indexed_records,
                )
            )

    return DatasetValidationReport(
        valid_records=tuple(record for _, record in valid),
        invalid_records=tuple(invalid),
        warnings=tuple(warnings),
        dataset_errors=tuple(errors),
    )
