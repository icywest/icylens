import json
import socket
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import joblib
import numpy as np
import pytest
from pydantic import ValidationError
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from app.ml.artifacts import export_dataset_artifact
from app.ml.builder import build_dataset, compute_dataset_digest
from app.ml.experiments import (
    ExperimentArtifactError,
    export_experiment,
    verify_experiment_artifact,
)
from app.ml.models import build_model_pipelines, effective_hyperparameters
from app.ml.preprocessing import (
    BOOLEAN_FEATURES,
    CATEGORICAL_FEATURES,
    NUMERIC_FEATURES,
    TRANSFORMED_FEATURE_COUNT,
    build_feature_matrix,
    build_labels,
    build_preprocessor,
    transformed_feature_names,
)
from app.ml.training import (
    TrainedExperiment,
    TrainingError,
    train_experiment,
    validate_training_dataset,
)
from app.schemas.ml_dataset import MLDatasetRecord
from app.schemas.ml_experiment import (
    HistGradientBoostingConfiguration,
    LogisticRegressionConfiguration,
    RandomForestConfiguration,
    TrainingConfiguration,
)
from app.schemas.ml_features import PREDICTIVE_FEATURE_ORDER
from app.schemas.ml_manifest import DatasetManifest
from scripts.train_models import main as training_cli_main
from tests.test_ml_dataset_pipeline import record_payload

CREATED_AT = datetime(2026, 10, 25, 20, tzinfo=UTC)


def synthetic_records(per_label: int = 20) -> list[MLDatasetRecord]:
    records: list[MLDatasetRecord] = []
    for label, start in (("benign", 1), ("malicious", 10_001)):
        for number in range(start, start + per_label):
            payload = record_payload(
                number,
                label=label,
                source_kind="synthetic",
                dataset_id="safe-synthetic-training-v1",
                synthetic=True,
            )
            payload["features"]["detected_format"] = "pdf" if number % 2 else "unknown"
            payload["features"]["format_consistency"] = (
                "match" if number % 3 else "unknown"
            )
            payload["features"]["has_url_candidate"] = number % 5 == 0
            payload["features"]["has_script_reference"] = number % 7 == 0
            records.append(MLDatasetRecord.model_validate(payload))
    return records


def owned_records(per_label: int = 20) -> list[MLDatasetRecord]:
    return [
        MLDatasetRecord.model_validate(record_payload(number, label=label))
        for label, start in (("benign", 1), ("malicious", 10_001))
        for number in range(start, start + per_label)
    ]


def fast_configuration(**updates: object) -> TrainingConfiguration:
    values: dict[str, object] = {
        "random_seed": 42,
        "logistic_regression": LogisticRegressionConfiguration(maximum_iterations=200),
        "random_forest": RandomForestConfiguration(estimator_count=10),
        "hist_gradient_boosting": HistGradientBoostingConfiguration(
            maximum_iterations=10,
            minimum_samples_per_leaf=2,
        ),
    }
    values.update(updates)
    return TrainingConfiguration.model_validate(values)


def build_synthetic_dataset(per_label: int = 20):
    return build_dataset(
        synthetic_records(per_label),
        dataset_id="safe-synthetic-training",
        dataset_version="1.0.0",
        created_at=CREATED_AT,
    )


def refresh_manifest(
    manifest: DatasetManifest,
    records: tuple[MLDatasetRecord, ...],
    **updates: object,
) -> DatasetManifest:
    label_counts = Counter(record.label.value for record in records)
    split_counts = Counter(record.split for record in records)
    values: dict[str, object] = {
        "record_count": len(records),
        "eligible_record_count": len(records),
        "label_counts": dict(sorted(label_counts.items())),
        "split_counts": {
            split: split_counts[split] for split in ("training", "validation", "test")
        },
        "source_identifiers": tuple(
            sorted({record.provenance.dataset_id for record in records})
        ),
        "extraction_versions": tuple(
            sorted({record.extraction.extractor_version for record in records})
        ),
    }
    values.update(updates)
    provisional = manifest.model_copy(update=values)
    digest = compute_dataset_digest(
        provisional.dataset_id,
        provisional.dataset_version,
        records,
        provisional.split_configuration,
    )
    return provisional.model_copy(update={"content_integrity_digest": digest})


@pytest.fixture(scope="module")
def synthetic_dataset():
    return build_synthetic_dataset()


@pytest.fixture(scope="module")
def trained_experiment(synthetic_dataset) -> TrainedExperiment:
    return train_experiment(
        synthetic_dataset.manifest,
        synthetic_dataset.records,
        experiment_id="synthetic-smoke-test",
        configuration=fast_configuration(),
        created_at=CREATED_AT,
    )


@pytest.mark.unit
def test_feature_groups_preserve_the_versioned_fourteen_feature_contract() -> None:
    assert (*NUMERIC_FEATURES, *CATEGORICAL_FEATURES, *BOOLEAN_FEATURES) == (
        PREDICTIVE_FEATURE_ORDER
    )
    assert len(NUMERIC_FEATURES) == 5
    assert len(CATEGORICAL_FEATURES) == 2
    assert len(BOOLEAN_FEATURES) == 7


@pytest.mark.unit
def test_feature_matrix_has_deterministic_types_and_no_identity_leakage() -> None:
    record = synthetic_records(1)[0]
    matrix = build_feature_matrix([record])
    labels = build_labels([record])

    assert matrix.shape == (1, 14)
    assert all(isinstance(value, float) for value in matrix[0, :5])
    assert all(isinstance(value, str) for value in matrix[0, 5:7])
    assert all(value in {0, 1} for value in matrix[0, 7:])
    assert labels.tolist() == ["benign"]
    serialized = repr(matrix.tolist())
    assert record.identity.sha256 not in serialized
    assert record.identity.record_id not in serialized
    assert record.provenance.dataset_id not in serialized


@pytest.mark.unit
def test_missing_feature_and_schema_mismatch_are_rejected_before_matrix() -> None:
    payload = record_payload(1)
    del payload["features"]["shannon_entropy"]
    with pytest.raises(ValidationError):
        MLDatasetRecord.model_validate(payload)

    payload = record_payload(1)
    payload["features"]["feature_schema_version"] = "2.0.0"
    with pytest.raises(ValidationError):
        MLDatasetRecord.model_validate(payload)


@pytest.mark.unit
def test_preprocessor_has_stable_nonordinal_encoding_and_unseen_category_support() -> (
    None
):
    training = synthetic_records(2)
    validation_payload = record_payload(999, label="benign")
    validation_payload["features"]["detected_format"] = "pe"
    validation = MLDatasetRecord.model_validate(validation_payload)
    preprocessor = build_preprocessor("standard_scaler")

    transformed_training = preprocessor.fit_transform(build_feature_matrix(training))
    transformed_validation = preprocessor.transform(build_feature_matrix([validation]))

    assert transformed_training.shape[1] == TRANSFORMED_FEATURE_COUNT == 23
    assert transformed_validation.shape == (1, 23)
    assert np.isfinite(transformed_validation).all()
    names = tuple(str(value) for value in preprocessor.get_feature_names_out())
    assert "categorical__x5_pe" in names


@pytest.mark.unit
def test_model_factory_builds_three_bounded_pipelines() -> None:
    configuration = fast_configuration()
    pipelines = build_model_pipelines(configuration)

    assert set(pipelines) == {
        "logistic_regression",
        "random_forest",
        "hist_gradient_boosting",
    }
    assert all(isinstance(value, Pipeline) for value in pipelines.values())
    assert isinstance(pipelines["logistic_regression"]["model"], LogisticRegression)
    assert isinstance(pipelines["random_forest"]["model"], RandomForestClassifier)
    assert isinstance(
        pipelines["hist_gradient_boosting"]["model"],
        HistGradientBoostingClassifier,
    )
    assert effective_hyperparameters("random_forest", configuration)["n_jobs"] == 1


@pytest.mark.unit
@pytest.mark.parametrize(
    ("model", "values"),
    [
        (LogisticRegressionConfiguration, {"maximum_iterations": 10}),
        (RandomForestConfiguration, {"estimator_count": 501}),
        (HistGradientBoostingConfiguration, {"learning_rate": 0}),
        (TrainingConfiguration, {"maximum_transformed_features": 13}),
    ],
)
def test_invalid_resource_and_model_parameters_are_rejected(
    model: type, values: dict[str, object]
) -> None:
    with pytest.raises(ValidationError):
        model.model_validate(values)


@pytest.mark.integration
def test_all_three_models_train_and_report_validation_only(
    trained_experiment: TrainedExperiment,
) -> None:
    report = trained_experiment.report

    assert report.mode == "synthetic_demo"
    assert report.scientific_representativeness == "not_established"
    assert report.test_set_accessed is False
    assert {model.algorithm for model in report.models} == set(
        trained_experiment.pipelines
    )
    assert report.training_record_count == 28
    assert report.validation_record_count == 6
    assert all(
        sum(model.validation_metrics.validation_support.values()) == 6
        for model in report.models
    )


@pytest.mark.integration
def test_logistic_scaler_is_fit_only_on_training(
    synthetic_dataset, trained_experiment: TrainedExperiment
) -> None:
    training = [
        record for record in synthetic_dataset.records if record.split == "training"
    ]
    matrix = build_feature_matrix(training)
    pipeline = trained_experiment.pipelines["logistic_regression"]
    preprocessor = pipeline["preprocessing"]

    assert isinstance(preprocessor, ColumnTransformer)
    scaler = preprocessor.named_transformers_["numeric"]
    assert isinstance(scaler, StandardScaler)
    assert np.allclose(scaler.mean_, matrix[:, :5].astype(float).mean(axis=0))


@pytest.mark.security
def test_training_never_builds_a_test_feature_matrix(
    synthetic_dataset, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.ml import training as training_module

    observed_splits: list[set[str]] = []
    original = training_module.build_feature_matrix

    def record_splits(records: tuple[MLDatasetRecord, ...]):
        observed_splits.append({record.split for record in records})
        return original(records)

    monkeypatch.setattr(training_module, "build_feature_matrix", record_splits)
    train_experiment(
        synthetic_dataset.manifest,
        synthetic_dataset.records,
        experiment_id="no-test-access",
        configuration=fast_configuration(),
        created_at=CREATED_AT,
    )

    assert observed_splits == [{"training"}, {"validation"}]
    assert {"test"} not in observed_splits


@pytest.mark.unit
def test_corrupted_dataset_integrity_is_rejected(synthetic_dataset) -> None:
    corrupted = list(synthetic_dataset.records)
    corrupted[0] = corrupted[0].model_copy(
        update={
            "features": corrupted[0].features.model_copy(
                update={"file_size_bytes": 999_999}
            )
        }
    )

    with pytest.raises(TrainingError) as error:
        validate_training_dataset(
            synthetic_dataset.manifest,
            corrupted,
            fast_configuration(),
        )

    assert error.value.code == "dataset_integrity_failed"


@pytest.mark.unit
def test_insufficient_training_class_support_is_rejected(synthetic_dataset) -> None:
    records = tuple(
        record.model_copy(update={"split": "test"})
        if record.label.value == "malicious" and record.split == "training"
        else record
        for record in synthetic_dataset.records
    )
    manifest = refresh_manifest(synthetic_dataset.manifest, records)

    with pytest.raises(TrainingError) as error:
        validate_training_dataset(manifest, records, fast_configuration())

    assert error.value.code == "insufficient_class_support"


@pytest.mark.unit
def test_single_class_training_is_rejected(synthetic_dataset) -> None:
    records = tuple(
        record.model_copy(update={"split": "test"})
        if record.label.value == "malicious"
        else record
        for record in synthetic_dataset.records
    )
    manifest = refresh_manifest(synthetic_dataset.manifest, records)

    with pytest.raises(TrainingError) as error:
        validate_training_dataset(manifest, records, fast_configuration())

    assert error.value.code == "insufficient_class_support"


@pytest.mark.unit
def test_dataset_size_limit_is_enforced(synthetic_dataset) -> None:
    configuration = fast_configuration(maximum_dataset_records=6)

    with pytest.raises(TrainingError) as error:
        validate_training_dataset(
            synthetic_dataset.manifest,
            synthetic_dataset.records,
            configuration,
        )

    assert error.value.code == "dataset_too_large"


@pytest.mark.unit
def test_mixed_synthetic_and_real_provenance_is_rejected(synthetic_dataset) -> None:
    records = list(synthetic_dataset.records)
    first = records[0]
    records[0] = first.model_copy(
        update={
            "provenance": first.provenance.model_copy(update={"source_kind": "owned"}),
            "label": first.label.model_copy(update={"synthetic": False}),
        }
    )
    values = tuple(records)
    manifest = refresh_manifest(synthetic_dataset.manifest, values)

    with pytest.raises(TrainingError) as error:
        validate_training_dataset(manifest, values, fast_configuration())

    assert error.value.code == "mixed_synthetic_and_real"


@pytest.mark.integration
def test_non_synthetic_dataset_is_marked_research_not_representative() -> None:
    dataset = build_dataset(
        owned_records(),
        dataset_id="owned-research",
        dataset_version="1",
        created_at=CREATED_AT,
    )
    trained = train_experiment(
        dataset.manifest,
        dataset.records,
        experiment_id="research-mode",
        configuration=fast_configuration(),
        created_at=CREATED_AT,
    )

    assert trained.report.mode == "research_evaluation"
    assert trained.report.scientific_representativeness == "not_established"


@pytest.mark.unit
def test_invalid_experiment_id_is_rejected_before_training(synthetic_dataset) -> None:
    with pytest.raises(TrainingError) as error:
        train_experiment(
            synthetic_dataset.manifest,
            synthetic_dataset.records,
            experiment_id="../escape",
            configuration=fast_configuration(),
        )

    assert error.value.code == "invalid_experiment_id"


@pytest.mark.integration
def test_seeded_training_reproduces_predictions_and_metrics(synthetic_dataset) -> None:
    first = train_experiment(
        synthetic_dataset.manifest,
        synthetic_dataset.records,
        experiment_id="repeat-one",
        configuration=fast_configuration(),
        created_at=CREATED_AT,
    )
    second = train_experiment(
        synthetic_dataset.manifest,
        synthetic_dataset.records,
        experiment_id="repeat-two",
        configuration=fast_configuration(),
        created_at=CREATED_AT,
    )
    validation = tuple(
        record for record in synthetic_dataset.records if record.split == "validation"
    )
    matrix = build_feature_matrix(validation)

    assert [model.validation_metrics for model in first.report.models] == [
        model.validation_metrics for model in second.report.models
    ]
    for algorithm in first.pipelines:
        assert np.array_equal(
            first.pipelines[algorithm].predict(matrix),
            second.pipelines[algorithm].predict(matrix),
        )


@pytest.mark.contract
def test_experiment_metadata_is_complete_and_serializable(
    trained_experiment: TrainedExperiment,
) -> None:
    report = trained_experiment.report
    payload = json.loads(report.model_dump_json())

    assert payload["dataset_integrity_digest"]
    assert payload["feature_schema_version"] == "1.0.0"
    assert payload["experiment_schema_version"] == "1.0.0"
    assert payload["training_pipeline_version"] == "training-pipeline/1.0.0"
    assert payload["python_version"]
    assert payload["numpy_version"]
    assert payload["scikit_learn_version"]
    assert payload["joblib_version"]
    assert payload["preprocessing"]["fit_partition"] == "training"
    assert payload["preprocessing"]["transformed_feature_count"] == 23


@pytest.mark.integration
def test_experiment_artifact_round_trip_without_deserialization(
    tmp_path: Path, trained_experiment: TrainedExperiment
) -> None:
    destination, manifest = export_experiment(trained_experiment, tmp_path)
    verified = verify_experiment_artifact(destination)

    assert verified == manifest
    assert (destination / "validation_metrics.json").is_file()
    assert len(list((destination / "models").glob("*.joblib"))) == 3
    assert all(item.size_bytes > 0 for item in manifest.model_artifacts)


@pytest.mark.security
def test_verification_never_deserializes_model_files(
    tmp_path: Path,
    trained_experiment: TrainedExperiment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination, _ = export_experiment(trained_experiment, tmp_path)

    def reject_load(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("model deserialization attempted")

    monkeypatch.setattr(joblib, "load", reject_load)
    assert verify_experiment_artifact(destination).report.test_set_accessed is False


@pytest.mark.security
def test_experiment_export_never_overwrites(
    tmp_path: Path, trained_experiment: TrainedExperiment
) -> None:
    export_experiment(trained_experiment, tmp_path)

    with pytest.raises(ExperimentArtifactError) as error:
        export_experiment(trained_experiment, tmp_path)

    assert error.value.code == "experiment_exists"


@pytest.mark.security
def test_model_artifact_tampering_is_detected(
    tmp_path: Path, trained_experiment: TrainedExperiment
) -> None:
    destination, manifest = export_experiment(trained_experiment, tmp_path)
    model_path = destination / manifest.model_artifacts[0].relative_path
    with model_path.open("ab") as stream:
        stream.write(b"tampered")

    with pytest.raises(ExperimentArtifactError) as error:
        verify_experiment_artifact(destination)

    assert error.value.code == "model_integrity_mismatch"


@pytest.mark.security
def test_export_cleans_staging_on_serialization_failure(
    tmp_path: Path,
    trained_experiment: TrainedExperiment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_dump(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise OSError("synthetic serialization failure")

    monkeypatch.setattr(joblib, "dump", fail_dump)
    with pytest.raises(OSError, match="synthetic serialization failure"):
        export_experiment(trained_experiment, tmp_path)

    assert list(tmp_path.glob(".training-*")) == []
    assert not (tmp_path / trained_experiment.report.experiment_id).exists()


@pytest.mark.security
def test_model_artifact_size_limit_is_enforced_and_cleaned(
    tmp_path: Path, trained_experiment: TrainedExperiment
) -> None:
    limited = TrainedExperiment(
        report=trained_experiment.report.model_copy(
            update={"experiment_id": "size-limited"}
        ),
        pipelines=trained_experiment.pipelines,
        configuration=trained_experiment.configuration.model_copy(
            update={"maximum_model_artifact_bytes": 1024}
        ),
    )

    with pytest.raises(ExperimentArtifactError) as error:
        export_experiment(limited, tmp_path)

    assert error.value.code == "model_artifact_too_large"
    assert list(tmp_path.glob(".training-*")) == []


@pytest.mark.security
def test_training_performs_no_network_or_binary_execution(
    synthetic_dataset, monkeypatch: pytest.MonkeyPatch
) -> None:
    def reject_network(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "create_connection", reject_network)
    result = train_experiment(
        synthetic_dataset.manifest,
        synthetic_dataset.records,
        experiment_id="offline-training",
        configuration=fast_configuration(),
        created_at=CREATED_AT,
    )

    assert result.report.test_set_accessed is False


@pytest.mark.integration
def test_training_cli_builds_and_reports_synthetic_notice(
    tmp_path: Path,
    synthetic_dataset,
    capsys: pytest.CaptureFixture[str],
) -> None:
    dataset_path = export_dataset_artifact(synthetic_dataset, tmp_path / "datasets")
    output = tmp_path / "experiments"

    exit_code = training_cli_main(
        [
            "--dataset",
            str(dataset_path),
            "--output",
            str(output),
            "--experiment-id",
            "cli-smoke",
            "--seed",
            "42",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["mode"] == "synthetic_demo"
    assert "not evidence" in payload["notice"]
    assert payload["test_set_accessed"] is False
    assert set(payload["models"]) == {
        "logistic_regression",
        "random_forest",
        "hist_gradient_boosting",
    }


@pytest.mark.integration
def test_training_cli_returns_nonzero_for_insufficient_dataset(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    tiny = build_synthetic_dataset(3)
    dataset_path = export_dataset_artifact(tiny, tmp_path / "datasets")

    exit_code = training_cli_main(
        [
            "--dataset",
            str(dataset_path),
            "--output",
            str(tmp_path / "experiments"),
            "--experiment-id",
            "too-small",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert payload["code"] == "insufficient_class_support"
    assert not (tmp_path / "experiments" / "too-small").exists()


@pytest.mark.unit
def test_transformed_feature_names_are_stable(trained_experiment) -> None:
    names = {
        transformed_feature_names(pipeline)
        for pipeline in trained_experiment.pipelines.values()
    }

    assert len(names) == 1
    assert len(names.pop()) == TRANSFORMED_FEATURE_COUNT
