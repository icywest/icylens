import json
import os
import shutil
import tempfile
from pathlib import Path

from pydantic import ValidationError

from app.ml.builder import (
    BuildValidationReport,
    DatasetBuildResult,
    summarize_validation_report,
    verify_dataset_integrity,
)
from app.ml.importing import (
    DatasetImportError,
    DatasetImportLimits,
    load_dataset_records,
)
from app.schemas.ml_dataset import MLDatasetRecord
from app.schemas.ml_manifest import DatasetManifest


class DatasetArtifactError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _json_text(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def export_dataset_artifact(
    result: DatasetBuildResult,
    output_root: Path,
) -> Path:
    root = output_root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    dataset_root = root / result.manifest.dataset_id
    if dataset_root.exists() and (
        dataset_root.is_symlink() or not dataset_root.resolve().is_relative_to(root)
    ):
        raise DatasetArtifactError(
            "unsafe_output_path", "dataset output path is not a safe child directory"
        )
    destination = dataset_root / result.manifest.dataset_version
    if destination.exists():
        raise DatasetArtifactError(
            "artifact_exists", "dataset artifact already exists; overwrite is forbidden"
        )
    dataset_root.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".building-", dir=dataset_root))
    try:
        records_text = "".join(
            json.dumps(
                record.model_dump(mode="json"),
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
            for record in result.records
        )
        (staging / "records.jsonl").write_text(records_text, encoding="utf-8")
        (staging / "manifest.json").write_text(
            _json_text(result.manifest.model_dump(mode="json")),
            encoding="utf-8",
        )
        (staging / "validation_report.json").write_text(
            _json_text(result.validation_report.model_dump(mode="json")),
            encoding="utf-8",
        )
        os.replace(staging, destination)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return destination


def load_and_verify_artifact(
    artifact_directory: Path,
    limits: DatasetImportLimits | None = None,
) -> tuple[DatasetManifest, tuple[MLDatasetRecord, ...]]:
    limits = limits or DatasetImportLimits()
    try:
        manifest_path = artifact_directory / "manifest.json"
        with manifest_path.open("rb") as stream:
            manifest_bytes = stream.read(limits.maximum_jsonl_line_bytes + 1)
    except OSError as error:
        raise DatasetArtifactError(
            "manifest_unreadable", "manifest cannot be read"
        ) from error
    if len(manifest_bytes) > limits.maximum_jsonl_line_bytes:
        raise DatasetArtifactError("manifest_too_large", "manifest exceeds byte limit")
    try:
        manifest = DatasetManifest.model_validate_json(manifest_bytes)
    except ValidationError as error:
        raise DatasetArtifactError(
            "invalid_manifest", "manifest failed schema validation"
        ) from error
    try:
        report_path = artifact_directory / "validation_report.json"
        with report_path.open("rb") as stream:
            report_bytes = stream.read(limits.maximum_jsonl_line_bytes + 1)
    except OSError as error:
        raise DatasetArtifactError(
            "validation_report_unreadable", "validation report cannot be read"
        ) from error
    if len(report_bytes) > limits.maximum_jsonl_line_bytes:
        raise DatasetArtifactError(
            "validation_report_too_large", "validation report exceeds byte limit"
        )
    try:
        validation_report = BuildValidationReport.model_validate_json(report_bytes)
    except ValidationError as error:
        raise DatasetArtifactError(
            "invalid_validation_report", "validation report failed schema validation"
        ) from error
    if summarize_validation_report(validation_report) != manifest.validation_summary:
        raise DatasetArtifactError(
            "validation_summary_mismatch",
            "validation report does not match the manifest summary",
        )
    try:
        raw_records = load_dataset_records(artifact_directory / "records.jsonl", limits)
        records = tuple(
            MLDatasetRecord.model_validate(record) for record in raw_records
        )
    except (DatasetImportError, ValidationError) as error:
        raise DatasetArtifactError(
            "invalid_records_artifact", "records artifact failed validation"
        ) from error
    if not verify_dataset_integrity(manifest, records):
        raise DatasetArtifactError(
            "integrity_mismatch", "artifact content digest does not match"
        )
    return manifest, records
