import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path

from pydantic import ValidationError

from app.ml.evaluation import EvaluatedExperiment
from app.schemas.ml_evaluation import EvaluationArtifactManifest, EvaluationReport

MAXIMUM_EVALUATION_JSON_BYTES = 5 * 1024 * 1024


class EvaluationArtifactError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def _read_bounded(path: Path) -> bytes:
    try:
        with path.open("rb") as stream:
            content = stream.read(MAXIMUM_EVALUATION_JSON_BYTES + 1)
    except OSError as error:
        raise EvaluationArtifactError(
            "evaluation_artifact_unreadable", "evaluation artifact cannot be read"
        ) from error
    if len(content) > MAXIMUM_EVALUATION_JSON_BYTES:
        raise EvaluationArtifactError(
            "evaluation_artifact_too_large", "evaluation artifact exceeds byte limit"
        )
    return content


def export_evaluation(
    evaluation: EvaluatedExperiment, output_root: Path
) -> tuple[Path, EvaluationArtifactManifest]:
    root = output_root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    destination = root / evaluation.report.evaluation_id
    if destination.exists():
        raise EvaluationArtifactError(
            "evaluation_exists", "evaluation overwrite is forbidden"
        )
    staging = Path(tempfile.mkdtemp(prefix=".evaluation-", dir=root))
    try:
        report_content = _json_bytes(evaluation.report.model_dump(mode="json"))
        if len(report_content) > MAXIMUM_EVALUATION_JSON_BYTES:
            raise EvaluationArtifactError(
                "evaluation_artifact_too_large", "evaluation report exceeds byte limit"
            )
        manifest = EvaluationArtifactManifest(
            report=evaluation.report,
            report_sha256=hashlib.sha256(report_content).hexdigest(),
            report_size_bytes=len(report_content),
        )
        (staging / "evaluation_report.json").write_bytes(report_content)
        (staging / "evaluation_manifest.json").write_bytes(
            _json_bytes(manifest.model_dump(mode="json"))
        )
        os.replace(staging, destination)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return destination, manifest


def verify_evaluation_artifact(artifact_directory: Path) -> EvaluationArtifactManifest:
    manifest_content = _read_bounded(artifact_directory / "evaluation_manifest.json")
    report_content = _read_bounded(artifact_directory / "evaluation_report.json")
    try:
        manifest = EvaluationArtifactManifest.model_validate_json(manifest_content)
        report = EvaluationReport.model_validate_json(report_content)
    except ValidationError as error:
        raise EvaluationArtifactError(
            "invalid_evaluation_artifact", "evaluation artifact contract is invalid"
        ) from error
    if (
        len(report_content) != manifest.report_size_bytes
        or hashlib.sha256(report_content).hexdigest() != manifest.report_sha256
        or report != manifest.report
    ):
        raise EvaluationArtifactError(
            "evaluation_integrity_mismatch", "evaluation report integrity differs"
        )
    return manifest
