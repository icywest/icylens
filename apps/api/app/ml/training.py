import platform
import re
import warnings
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

import joblib  # type: ignore[import-untyped]
import numpy as np
import sklearn  # type: ignore[import-untyped]
from numpy.typing import NDArray
from sklearn.exceptions import ConvergenceWarning  # type: ignore[import-untyped]
from sklearn.metrics import (  # type: ignore[import-untyped]
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.pipeline import Pipeline  # type: ignore[import-untyped]

from app.ml.builder import verify_dataset_integrity
from app.ml.models import build_model_pipelines, effective_hyperparameters
from app.ml.preprocessing import (
    TRANSFORMED_FEATURE_COUNT,
    build_feature_matrix,
    build_labels,
    preprocessing_configuration,
    transformed_feature_names,
)
from app.schemas.ml_dataset import MLDatasetRecord
from app.schemas.ml_experiment import (
    ExperimentMode,
    ExperimentReport,
    ModelAlgorithm,
    ModelRunReport,
    TrainingConfiguration,
    ValidationMetrics,
)
from app.schemas.ml_manifest import DatasetManifest

SUPPORTED_EXTRACTION_VERSIONS = {"static-analysis-adapter/1.0.0"}
LABELS = ("benign", "malicious")


class TrainingError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class TrainedExperiment:
    report: ExperimentReport
    pipelines: dict[ModelAlgorithm, Pipeline]
    configuration: TrainingConfiguration


def _class_counts(records: Sequence[MLDatasetRecord]) -> dict[str, int]:
    counts: Counter[str] = Counter(record.label.value for record in records)
    return {label: counts[label] for label in LABELS}


def _require_minimum_counts(
    records: Sequence[MLDatasetRecord],
    minimum: int,
    partition: str,
) -> None:
    counts = _class_counts(records)
    if any(counts[label] < minimum for label in LABELS):
        raise TrainingError(
            "insufficient_class_support",
            f"{partition} requires at least {minimum} records per class",
        )


def _experiment_mode(records: Sequence[MLDatasetRecord]) -> ExperimentMode:
    synthetic = [
        record.provenance.source_kind == "synthetic" or record.label.synthetic
        for record in records
    ]
    if any(synthetic):
        if not all(
            record.provenance.source_kind == "synthetic" and record.label.synthetic
            for record in records
        ):
            raise TrainingError(
                "mixed_synthetic_and_real",
                "synthetic and non-synthetic records cannot share one experiment",
            )
        return "synthetic_demo"
    return "research_evaluation"


def validate_training_dataset(
    manifest: DatasetManifest,
    records: Sequence[MLDatasetRecord],
    configuration: TrainingConfiguration,
) -> tuple[tuple[MLDatasetRecord, ...], tuple[MLDatasetRecord, ...], ExperimentMode]:
    if not verify_dataset_integrity(manifest, records):
        raise TrainingError("dataset_integrity_failed", "dataset integrity is invalid")
    if not manifest.validation_summary.ready_for_training:
        raise TrainingError("dataset_not_ready", "dataset is not training eligible")
    if manifest.feature_schema_version != configuration.feature_schema_version:
        raise TrainingError("feature_schema_mismatch", "feature schema is incompatible")
    if not set(manifest.extraction_versions) <= SUPPORTED_EXTRACTION_VERSIONS:
        raise TrainingError(
            "unsupported_extraction_version", "extraction version is unsupported"
        )
    if len(records) > configuration.maximum_dataset_records:
        raise TrainingError("dataset_too_large", "dataset exceeds the training limit")
    hashes = [record.identity.sha256 for record in records]
    if len(hashes) != len(set(hashes)):
        raise TrainingError("duplicate_sha256", "duplicate identities are not allowed")
    if any(record.label.value == "unknown" for record in records):
        raise TrainingError("unknown_label", "unknown labels cannot be trained")
    if any(record.split == "unassigned" for record in records):
        raise TrainingError("unassigned_split", "all released records need a split")

    mode = _experiment_mode(records)
    training = tuple(record for record in records if record.split == "training")
    validation = tuple(record for record in records if record.split == "validation")
    test_records = tuple(record for record in records if record.split == "test")
    _require_minimum_counts(
        training,
        configuration.minimum_training_records_per_class,
        "training",
    )
    _require_minimum_counts(
        validation,
        configuration.minimum_validation_records_per_class,
        "validation",
    )
    _require_minimum_counts(test_records, 1, "sealed test")
    return training, validation, mode


def _validation_metrics(
    expected: NDArray[np.str_],
    predicted: NDArray[np.str_],
) -> ValidationMetrics:
    expected_values = [str(value) for value in expected]
    predicted_values = [str(value) for value in predicted]
    matrix = confusion_matrix(expected_values, predicted_values, labels=list(LABELS))
    actual_counts = Counter(expected_values)
    prediction_counts = Counter(predicted_values)
    undefined: list[str] = []
    if prediction_counts["malicious"] == 0:
        undefined.append("precision_malicious")
    if actual_counts["malicious"] == 0:
        undefined.extend(("recall_malicious", "f1_malicious"))
    return ValidationMetrics(
        confusion_matrix=(
            (int(matrix[0, 0]), int(matrix[0, 1])),
            (int(matrix[1, 0]), int(matrix[1, 1])),
        ),
        precision_malicious=float(
            precision_score(
                expected_values,
                predicted_values,
                pos_label="malicious",
                zero_division=0,
            )
        ),
        recall_malicious=float(
            recall_score(
                expected_values,
                predicted_values,
                pos_label="malicious",
                zero_division=0,
            )
        ),
        f1_malicious=float(
            f1_score(
                expected_values,
                predicted_values,
                pos_label="malicious",
                zero_division=0,
            )
        ),
        balanced_accuracy=float(
            balanced_accuracy_score(expected_values, predicted_values)
        ),
        validation_support={label: actual_counts[label] for label in LABELS},
        prediction_counts={label: prediction_counts[label] for label in LABELS},
        undefined_metrics=tuple(undefined),
    )


def train_experiment(
    manifest: DatasetManifest,
    records: Sequence[MLDatasetRecord],
    *,
    experiment_id: str,
    configuration: TrainingConfiguration | None = None,
    created_at: datetime | None = None,
) -> TrainedExperiment:
    if re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", experiment_id) is None:
        raise TrainingError(
            "invalid_experiment_id", "experiment ID is not a safe path component"
        )
    configuration = configuration or TrainingConfiguration()
    training, validation, mode = validate_training_dataset(
        manifest, records, configuration
    )
    training_matrix = build_feature_matrix(training)
    validation_matrix = build_feature_matrix(validation)
    training_labels = build_labels(training)
    validation_labels = build_labels(validation)
    pipelines = build_model_pipelines(configuration)
    reports: list[ModelRunReport] = []
    for algorithm, pipeline in pipelines.items():
        with warnings.catch_warnings():
            warnings.simplefilter("error", ConvergenceWarning)
            try:
                pipeline.fit(training_matrix, training_labels)
            except ConvergenceWarning as error:
                raise TrainingError(
                    "model_did_not_converge", f"{algorithm} did not converge"
                ) from error
        feature_names = transformed_feature_names(pipeline)
        if len(feature_names) != TRANSFORMED_FEATURE_COUNT:
            raise TrainingError(
                "transformed_feature_contract_mismatch",
                "preprocessing produced an unexpected feature count",
            )
        if len(feature_names) > configuration.maximum_transformed_features:
            raise TrainingError(
                "too_many_transformed_features",
                "transformed feature count exceeds the configured limit",
            )
        predictions = pipeline.predict(validation_matrix)
        reports.append(
            ModelRunReport(
                algorithm=algorithm,
                hyperparameters=effective_hyperparameters(algorithm, configuration),
                validation_metrics=_validation_metrics(validation_labels, predictions),
            )
        )

    timestamp = created_at or datetime.now(UTC)
    report = ExperimentReport(
        experiment_id=experiment_id,
        mode=mode,
        dataset_id=manifest.dataset_id,
        dataset_version=manifest.dataset_version,
        dataset_integrity_digest=manifest.content_integrity_digest,
        feature_schema_version=manifest.feature_schema_version,
        extraction_versions=manifest.extraction_versions,
        random_seed=configuration.random_seed,
        python_version=platform.python_version(),
        numpy_version=np.__version__,
        scikit_learn_version=sklearn.__version__,
        joblib_version=joblib.__version__,
        preprocessing=preprocessing_configuration(),
        training_record_count=len(training),
        validation_record_count=len(validation),
        training_class_distribution=_class_counts(training),
        validation_class_distribution=_class_counts(validation),
        created_at=timestamp,
        models=tuple(reports),
    )
    return TrainedExperiment(
        report=report,
        pipelines=pipelines,
        configuration=configuration,
    )
