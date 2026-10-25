import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path

import joblib  # type: ignore[import-untyped]
from pydantic import ValidationError

from app.ml.training import TrainedExperiment
from app.schemas.ml_experiment import (
    ExperimentManifest,
    ModelArtifactDescriptor,
)

EXPERIMENT_MANIFEST_MAX_BYTES = 1024 * 1024


class ExperimentArtifactError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _sha256_file(path: Path, maximum_bytes: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(64 * 1024):
            size += len(chunk)
            if size > maximum_bytes:
                raise ExperimentArtifactError(
                    "model_artifact_too_large",
                    "serialized model exceeds the configured limit",
                )
            digest.update(chunk)
    return digest.hexdigest(), size


def _json_text(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def export_experiment(
    experiment: TrainedExperiment,
    output_root: Path,
) -> tuple[Path, ExperimentManifest]:
    root = output_root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    destination = root / experiment.report.experiment_id
    if destination.exists():
        raise ExperimentArtifactError(
            "experiment_exists", "experiment overwrite is forbidden"
        )
    staging = Path(tempfile.mkdtemp(prefix=".training-", dir=root))
    try:
        models_directory = staging / "models"
        models_directory.mkdir()
        descriptors: list[ModelArtifactDescriptor] = []
        for algorithm in sorted(experiment.pipelines):
            path = models_directory / f"{algorithm}.joblib"
            joblib.dump(experiment.pipelines[algorithm], path, compress=3)
            digest, size = _sha256_file(
                path,
                experiment.configuration.maximum_model_artifact_bytes,
            )
            descriptors.append(
                ModelArtifactDescriptor(
                    algorithm=algorithm,
                    relative_path=f"models/{algorithm}.joblib",
                    sha256=digest,
                    size_bytes=size,
                )
            )
        manifest = ExperimentManifest(
            report=experiment.report,
            model_artifacts=tuple(descriptors),
        )
        (staging / "experiment.json").write_text(
            _json_text(manifest.model_dump(mode="json")),
            encoding="utf-8",
        )
        metrics = {
            model.algorithm: model.validation_metrics.model_dump(mode="json")
            for model in experiment.report.models
        }
        (staging / "validation_metrics.json").write_text(
            _json_text(metrics),
            encoding="utf-8",
        )
        os.replace(staging, destination)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return destination, manifest


def verify_experiment_artifact(
    artifact_directory: Path,
    *,
    maximum_model_artifact_bytes: int = 100 * 1024 * 1024,
) -> ExperimentManifest:
    try:
        with (artifact_directory / "experiment.json").open("rb") as stream:
            content = stream.read(EXPERIMENT_MANIFEST_MAX_BYTES + 1)
    except OSError as error:
        raise ExperimentArtifactError(
            "experiment_manifest_unreadable", "experiment manifest cannot be read"
        ) from error
    if len(content) > EXPERIMENT_MANIFEST_MAX_BYTES:
        raise ExperimentArtifactError(
            "experiment_manifest_too_large", "experiment manifest exceeds byte limit"
        )
    try:
        manifest = ExperimentManifest.model_validate_json(content)
    except ValidationError as error:
        raise ExperimentArtifactError(
            "invalid_experiment_manifest", "experiment manifest is invalid"
        ) from error

    root = artifact_directory.resolve()
    for descriptor in manifest.model_artifacts:
        path = (root / Path(descriptor.relative_path)).resolve()
        if not path.is_relative_to(root):
            raise ExperimentArtifactError(
                "unsafe_model_path", "model path escapes the experiment directory"
            )
        try:
            digest, size = _sha256_file(path, maximum_model_artifact_bytes)
        except OSError as error:
            raise ExperimentArtifactError(
                "model_artifact_unreadable", "model artifact cannot be read"
            ) from error
        if size != descriptor.size_bytes or digest != descriptor.sha256:
            raise ExperimentArtifactError(
                "model_integrity_mismatch", "model artifact digest or size differs"
            )
    return manifest
