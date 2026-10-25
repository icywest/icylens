import json
from datetime import UTC, datetime
from pathlib import Path

import joblib
import numpy as np
import pytest
from pydantic import ValidationError

from app.ml.artifacts import export_dataset_artifact
from app.ml.evaluation import (
    EvaluatedExperiment,
    EvaluationError,
    calculate_classification_metrics,
    calculate_probability_metrics,
    evaluate_experiment,
    select_candidate,
)
from app.ml.evaluation_artifacts import (
    EvaluationArtifactError,
    export_evaluation,
    verify_evaluation_artifact,
)
from app.ml.training import train_experiment
from app.schemas.ml_evaluation import (
    AvailableMetric,
    EvaluationConfiguration,
    ModelComparison,
    UnavailableMetric,
)
from scripts.evaluate_models import main as evaluation_cli_main
from tests.test_ml_training_pipeline import (
    build_synthetic_dataset,
    fast_configuration,
)

EVALUATED_AT = datetime(2026, 10, 25, 21, tzinfo=UTC)


@pytest.fixture(scope="module")
def evaluated_experiment():
    dataset = build_synthetic_dataset()
    trained = train_experiment(
        dataset.manifest,
        dataset.records,
        experiment_id="evaluation-test",
        configuration=fast_configuration(),
        created_at=EVALUATED_AT,
    )
    evaluated = evaluate_experiment(
        trained,
        dataset.manifest,
        dataset.records,
        evaluation_id="evaluation-test",
        configuration=EvaluationConfiguration(permutation_repeats=2),
        evaluated_at=EVALUATED_AT,
    )
    return dataset, trained, evaluated


@pytest.mark.unit
def test_perfect_classification_reference_case() -> None:
    metrics = calculate_classification_metrics(
        ["benign", "benign", "malicious", "malicious"],
        ["benign", "benign", "malicious", "malicious"],
    )

    assert metrics.confusion_matrix.model_dump(exclude={"label_order"}) == {
        "true_benign_predicted_benign": 2,
        "true_benign_predicted_malicious": 0,
        "true_malicious_predicted_benign": 0,
        "true_malicious_predicted_malicious": 2,
    }
    assert metrics.macro_f1.value == 1
    assert metrics.balanced_accuracy.value == 1


@pytest.mark.unit
@pytest.mark.parametrize(
    ("predicted", "false_positives", "false_negatives"),
    [
        (["benign"] * 4, 0, 2),
        (["malicious"] * 4, 2, 0),
        (["malicious", "benign", "benign", "malicious"], 1, 1),
    ],
)
def test_all_one_class_and_mixed_errors(
    predicted: list[str], false_positives: int, false_negatives: int
) -> None:
    metrics = calculate_classification_metrics(
        ["benign", "benign", "malicious", "malicious"], predicted
    )

    assert metrics.false_positive_count == false_positives
    assert metrics.false_negative_count == false_negatives


@pytest.mark.unit
def test_single_class_metrics_are_explicitly_unavailable() -> None:
    metrics = calculate_classification_metrics(
        ["benign", "benign"], ["benign", "benign"]
    )

    assert metrics.false_negative_rate.available is False
    assert metrics.balanced_accuracy.available is False
    assert metrics.per_class[1].recall.available is False
    assert metrics.macro_f1.available is False


@pytest.mark.unit
@pytest.mark.parametrize(
    ("expected", "predicted", "code"),
    [
        (["benign"], [], "invalid_prediction_shape"),
        (["unknown"], ["benign"], "invalid_label"),
    ],
)
def test_invalid_classification_input_is_rejected(
    expected: list[str], predicted: list[str], code: str
) -> None:
    with pytest.raises(EvaluationError) as error:
        calculate_classification_metrics(expected, predicted)

    assert error.value.code == code


@pytest.mark.unit
def test_probability_metrics_match_known_reference_values() -> None:
    metrics = calculate_probability_metrics(
        ["benign", "benign", "malicious", "malicious"],
        np.asarray([0.1, 0.4, 0.35, 0.8]),
        reliability_bin_count=5,
    )

    assert metrics.roc_auc.value == pytest.approx(0.75)
    assert metrics.average_precision.value == pytest.approx(5 / 6)
    assert metrics.brier_score.value == pytest.approx(0.158125)
    assert metrics.log_loss.value == pytest.approx(0.4722879538)
    assert sum(item.count for item in metrics.reliability_bins) == 4
    assert metrics.calibration_status == "not_established"


@pytest.mark.unit
def test_single_class_probability_ranking_is_unavailable() -> None:
    metrics = calculate_probability_metrics(
        ["benign", "benign"],
        np.asarray([0.1, 0.2]),
        reliability_bin_count=2,
    )

    assert metrics.roc_auc.available is False
    assert metrics.average_precision.available is False
    assert metrics.brier_score.available is True
    assert metrics.log_loss.available is True


@pytest.mark.unit
@pytest.mark.parametrize(
    ("probabilities", "code"),
    [
        (np.asarray([[0.1], [0.2]]), "invalid_probability_shape"),
        (np.asarray([0.1, np.nan]), "non_finite_probability"),
        (np.asarray([0.1, np.inf]), "non_finite_probability"),
        (np.asarray([0.1, 1.1]), "probability_out_of_range"),
    ],
)
def test_invalid_probabilities_are_rejected(
    probabilities: np.ndarray, code: str
) -> None:
    with pytest.raises(EvaluationError) as error:
        calculate_probability_metrics(
            ["benign", "malicious"],
            probabilities,
            reliability_bin_count=2,
        )

    assert error.value.code == code


@pytest.mark.unit
def test_schema_rejects_non_finite_reported_metric() -> None:
    with pytest.raises(ValidationError):
        AvailableMetric(value=float("nan"))


@pytest.mark.unit
@pytest.mark.parametrize(
    "values",
    [
        {"permutation_repeats": 21},
        {"threshold_candidates": (0.5, 0.3)},
        {"threshold_candidates": (0.5, 0.5)},
        {"threshold_candidates": tuple(index / 100 for index in range(1, 23))},
    ],
)
def test_evaluation_resource_bounds_are_typed(values: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        EvaluationConfiguration.model_validate(values)


@pytest.mark.integration
def test_evaluation_report_has_fixed_identity_and_positive_class(
    evaluated_experiment,
) -> None:
    dataset, trained, evaluated = evaluated_experiment
    report = evaluated.report

    assert report.experiment_id == trained.report.experiment_id
    assert report.dataset_integrity_digest == dataset.manifest.content_integrity_digest
    assert report.evaluated_split == "validation"
    assert report.label_order == ("benign", "malicious")
    assert report.positive_class == "malicious"
    assert report.test_set_accessed is False
    assert len(report.models) == 3


@pytest.mark.integration
def test_probability_column_maps_malicious_class_correctly(
    evaluated_experiment,
) -> None:
    dataset, trained, evaluated = evaluated_experiment
    validation = tuple(
        record for record in dataset.records if record.split == "validation"
    )
    from app.ml.preprocessing import build_feature_matrix

    matrix = build_feature_matrix(validation)
    model = trained.pipelines["logistic_regression"]
    malicious_column = list(model.classes_).index("malicious")
    probabilities = model.predict_proba(matrix)[:, malicious_column]
    expected = np.asarray([record.label.value == "malicious" for record in validation])
    manual_brier = float(np.mean((probabilities - expected) ** 2))
    report = next(
        item
        for item in evaluated.report.models
        if item.algorithm == "logistic_regression"
    )

    assert report.probability is not None
    assert report.probability.brier_score.value == pytest.approx(manual_brier)


@pytest.mark.integration
def test_threshold_analysis_is_non_destructive_and_bounded(
    evaluated_experiment,
) -> None:
    _, _, evaluated = evaluated_experiment

    for model in evaluated.report.models:
        assert tuple(item.threshold for item in model.thresholds) == (0.3, 0.5, 0.7)
        assert all(item.predicted_malicious_count <= 6 for item in model.thresholds)
    assert evaluated.report.selection.status == "insufficient_evidence"
    assert evaluated.report.selection.reason_code == "synthetic_evidence"


@pytest.mark.integration
def test_error_analysis_is_aggregate_and_privacy_conscious(
    evaluated_experiment,
) -> None:
    dataset, _, evaluated = evaluated_experiment
    payload = json.dumps(
        [
            item.error_analysis.model_dump(mode="json")
            for item in evaluated.report.models
        ]
    )

    assert all(
        item.error_analysis.correct_count
        + item.error_analysis.false_positive_count
        + item.error_analysis.false_negative_count
        == 6
        for item in evaluated.report.models
    )
    assert all(
        subgroup.warning == "small_subgroup_no_generalization"
        for model in evaluated.report.models
        for subgroup in model.error_analysis.subgroups
        if subgroup.support < 5
    )
    assert not any(record.identity.sha256 in payload for record in dataset.records)
    assert "record_id" not in payload


@pytest.mark.integration
def test_permutation_importance_is_original_feature_repeatable(
    evaluated_experiment,
) -> None:
    dataset, trained, first = evaluated_experiment
    second = evaluate_experiment(
        trained,
        dataset.manifest,
        dataset.records,
        evaluation_id="evaluation-repeat",
        configuration=EvaluationConfiguration(permutation_repeats=2),
        evaluated_at=EVALUATED_AT,
    )

    assert [item.feature_influences for item in first.report.models] == [
        item.feature_influences for item in second.report.models
    ]
    assert all(len(item.feature_influences) == 14 for item in first.report.models)
    assert all(
        influence.repeats == 2
        for item in first.report.models
        for influence in item.feature_influences
    )
    assert "causal" in " ".join(first.report.limitations.statements).lower()


@pytest.mark.security
def test_evaluation_builds_only_validation_feature_matrix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.ml import evaluation as evaluation_module

    dataset = build_synthetic_dataset()
    trained = train_experiment(
        dataset.manifest,
        dataset.records,
        experiment_id="isolation-test",
        configuration=fast_configuration(),
        created_at=EVALUATED_AT,
    )
    observed: list[set[str]] = []
    original = evaluation_module.build_feature_matrix

    def inspect_splits(records):
        observed.append({record.split for record in records})
        return original(records)

    monkeypatch.setattr(evaluation_module, "build_feature_matrix", inspect_splits)
    evaluate_experiment(
        trained,
        dataset.manifest,
        dataset.records,
        evaluation_id="isolation-test",
        configuration=EvaluationConfiguration(permutation_repeats=1),
        evaluated_at=EVALUATED_AT,
    )

    assert observed == [{"validation"}]


@pytest.mark.unit
def test_dataset_digest_mismatch_is_rejected(evaluated_experiment) -> None:
    dataset, trained, _ = evaluated_experiment
    incompatible = trained.report.model_copy(
        update={"dataset_integrity_digest": "0" * 64}
    )

    with pytest.raises(EvaluationError) as error:
        evaluate_experiment(
            trained.__class__(
                report=incompatible,
                pipelines=trained.pipelines,
                configuration=trained.configuration,
            ),
            dataset.manifest,
            dataset.records,
            evaluation_id="mismatch",
            configuration=EvaluationConfiguration(permutation_repeats=1),
        )

    assert error.value.code == "dataset_identity_mismatch"


def comparison(
    algorithm: str, score: float | None, *, support: int = 200, recall: float = 0.8
) -> ModelComparison:
    metric = (
        AvailableMetric(value=score)
        if score is not None
        else UnavailableMetric(reason="missing")
    )
    return ModelComparison(
        algorithm=algorithm,
        macro_f1=metric,
        malicious_recall=AvailableMetric(value=recall),
        false_positive_rate=AvailableMetric(value=0.1),
        balanced_accuracy=AvailableMetric(value=0.8),
        average_precision=AvailableMetric(value=0.8),
        validation_support=support,
    )


@pytest.mark.unit
def test_selection_is_order_independent_and_abstains_on_tie() -> None:
    values = [
        comparison("random_forest", 0.8),
        comparison("logistic_regression", 0.8),
        comparison("hist_gradient_boosting", 0.7),
    ]
    config = EvaluationConfiguration()

    first = select_candidate(values, mode="research_evaluation", configuration=config)
    second = select_candidate(
        list(reversed(values)), mode="research_evaluation", configuration=config
    )

    assert first == second
    assert first.status == "inconclusive_performance"


@pytest.mark.unit
def test_selection_handles_missing_metric_and_low_support() -> None:
    config = EvaluationConfiguration()
    missing = [
        comparison("logistic_regression", None),
        comparison("random_forest", 0.8),
        comparison("hist_gradient_boosting", 0.7),
    ]
    low_support = [
        item.model_copy(update={"validation_support": 10}) for item in missing
    ]

    assert (
        select_candidate(
            missing, mode="research_evaluation", configuration=config
        ).status
        == "validation_failure"
    )
    assert (
        select_candidate(
            low_support, mode="research_evaluation", configuration=config
        ).reason_code
        == "operational_support_policy"
    )


@pytest.mark.unit
def test_selection_requires_margin_and_recall_floor() -> None:
    config = EvaluationConfiguration()
    selectable = [
        comparison("logistic_regression", 0.9),
        comparison("random_forest", 0.8),
        comparison("hist_gradient_boosting", 0.7),
    ]
    low_recall = [
        selectable[0].model_copy(
            update={"malicious_recall": AvailableMetric(value=0.4)}
        ),
        *selectable[1:],
    ]

    selected = select_candidate(
        selectable, mode="research_evaluation", configuration=config
    )
    abstained = select_candidate(
        low_recall, mode="research_evaluation", configuration=config
    )

    assert selected.selected_candidate == "logistic_regression"
    assert abstained.reason_code == "minimum_quality_not_met"


@pytest.mark.integration
def test_evaluation_artifact_round_trip(evaluated_experiment, tmp_path: Path) -> None:
    _, _, evaluated = evaluated_experiment
    destination, manifest = export_evaluation(evaluated, tmp_path)

    assert verify_evaluation_artifact(destination) == manifest
    assert (destination / "evaluation_report.json").is_file()
    assert (destination / "evaluation_manifest.json").is_file()


@pytest.mark.security
def test_evaluation_artifact_never_overwrites(
    evaluated_experiment, tmp_path: Path
) -> None:
    _, _, evaluated = evaluated_experiment
    export_evaluation(evaluated, tmp_path)

    with pytest.raises(EvaluationArtifactError) as error:
        export_evaluation(evaluated, tmp_path)

    assert error.value.code == "evaluation_exists"


@pytest.mark.security
def test_evaluation_artifact_tampering_is_detected(
    evaluated_experiment, tmp_path: Path
) -> None:
    _, _, evaluated = evaluated_experiment
    destination, _ = export_evaluation(evaluated, tmp_path)
    with (destination / "evaluation_report.json").open("ab") as stream:
        stream.write(b" ")

    with pytest.raises(EvaluationArtifactError) as error:
        verify_evaluation_artifact(destination)

    assert error.value.code == "evaluation_integrity_mismatch"


@pytest.mark.security
def test_evaluation_never_deserializes_joblib(
    evaluated_experiment, monkeypatch: pytest.MonkeyPatch
) -> None:
    dataset, trained, _ = evaluated_experiment

    def reject_load(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("unsafe deserialization attempted")

    monkeypatch.setattr(joblib, "load", reject_load)
    result = evaluate_experiment(
        trained,
        dataset.manifest,
        dataset.records,
        evaluation_id="no-load",
        configuration=EvaluationConfiguration(permutation_repeats=1),
        evaluated_at=EVALUATED_AT,
    )

    assert result.report.test_set_accessed is False


@pytest.mark.integration
def test_evaluation_cli_exports_synthetic_abstention(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dataset = build_synthetic_dataset()
    dataset_path = export_dataset_artifact(dataset, tmp_path / "datasets")

    exit_code = evaluation_cli_main(
        [
            "--dataset",
            str(dataset_path),
            "--output",
            str(tmp_path / "evaluations"),
            "--experiment-id",
            "cli-experiment",
            "--evaluation-id",
            "cli-evaluation",
            "--permutation-repeats",
            "1",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["mode"] == "synthetic_demo"
    assert payload["selection"]["selected_candidate"] is None
    assert payload["test_set_accessed"] is False
    assert "not evidence" in payload["notice"]


@pytest.mark.integration
def test_evaluation_cli_rejects_invalid_configuration(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dataset = build_synthetic_dataset()
    dataset_path = export_dataset_artifact(dataset, tmp_path / "datasets")

    exit_code = evaluation_cli_main(
        [
            "--dataset",
            str(dataset_path),
            "--output",
            str(tmp_path / "evaluations"),
            "--experiment-id",
            "cli-experiment",
            "--evaluation-id",
            "cli-evaluation",
            "--permutation-repeats",
            "21",
        ]
    )

    assert exit_code == 2
    assert json.loads(capsys.readouterr().out)["code"] == "invalid_arguments"


@pytest.mark.unit
def test_evaluation_manifest_rejects_non_utc_timestamp(evaluated_experiment) -> None:
    _, _, evaluated = evaluated_experiment
    payload = evaluated.report.model_dump()
    payload["evaluated_at"] = datetime(2026, 1, 1)

    with pytest.raises(ValidationError):
        evaluated.report.__class__.model_validate(payload)


@pytest.mark.unit
def test_invalid_evaluation_id_is_rejected(evaluated_experiment) -> None:
    dataset, trained, _ = evaluated_experiment
    with pytest.raises(EvaluationError) as error:
        evaluate_experiment(
            trained,
            dataset.manifest,
            dataset.records,
            evaluation_id="../escape",
            configuration=EvaluationConfiguration(permutation_repeats=1),
        )

    assert error.value.code == "invalid_evaluation_id"


@pytest.mark.unit
def test_artifact_size_limit_is_enforced_without_partial_output(
    evaluated_experiment, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.ml import evaluation_artifacts

    _, _, evaluated = evaluated_experiment
    monkeypatch.setattr(evaluation_artifacts, "MAXIMUM_EVALUATION_JSON_BYTES", 10)

    with pytest.raises(EvaluationArtifactError) as error:
        export_evaluation(
            EvaluatedExperiment(evaluated.report, evaluated.configuration), tmp_path
        )

    assert error.value.code == "evaluation_artifact_too_large"
    assert not (tmp_path / evaluated.report.evaluation_id).exists()
    assert list(tmp_path.glob(".evaluation-*")) == []
