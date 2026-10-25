import math
import re
from collections import Counter, defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

import numpy as np
from numpy.typing import NDArray
from sklearn.inspection import permutation_importance  # type: ignore[import-untyped]
from sklearn.metrics import (  # type: ignore[import-untyped]
    average_precision_score,
    brier_score_loss,
    log_loss,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline  # type: ignore[import-untyped]

from app.ml.builder import verify_dataset_integrity
from app.ml.preprocessing import build_feature_matrix, build_labels
from app.ml.training import LABELS, TrainedExperiment
from app.schemas.ml_dataset import MLDatasetRecord
from app.schemas.ml_evaluation import (
    AvailableMetric,
    ClassificationMetrics,
    ClassMetrics,
    ConfusionMatrix,
    DistributionSummary,
    ErrorAnalysis,
    ErrorSubgroup,
    EvaluationConfiguration,
    EvaluationLimitations,
    EvaluationReport,
    FeatureInfluence,
    MetricResult,
    ModelComparison,
    ModelEvaluationReport,
    ModelSelectionDecision,
    ProbabilityMetrics,
    ReliabilityBin,
    ThresholdResult,
    UnavailableMetric,
)
from app.schemas.ml_features import PREDICTIVE_FEATURE_ORDER
from app.schemas.ml_manifest import DatasetManifest


class EvaluationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class EvaluatedExperiment:
    report: EvaluationReport
    configuration: EvaluationConfiguration


def _available(value: float) -> AvailableMetric:
    if not math.isfinite(value):
        raise EvaluationError("non_finite_metric", "a calculated metric is non-finite")
    return AvailableMetric(value=value)


def _unavailable(reason: str) -> UnavailableMetric:
    return UnavailableMetric(reason=reason)


def _ratio(numerator: int, denominator: int, reason: str) -> MetricResult:
    return _available(numerator / denominator) if denominator else _unavailable(reason)


def _metric_value(metric: MetricResult) -> float | None:
    return metric.value if metric.available else None


def _required_metric_value(metric: MetricResult) -> float:
    value = _metric_value(metric)
    if value is None:
        raise EvaluationError("metric_unavailable", "required metric is unavailable")
    return value


def calculate_classification_metrics(
    expected: Sequence[str], predicted: Sequence[str]
) -> ClassificationMetrics:
    if len(expected) != len(predicted) or not expected:
        raise EvaluationError(
            "invalid_prediction_shape", "expected and predicted labels must align"
        )
    if any(value not in LABELS for value in (*expected, *predicted)):
        raise EvaluationError("invalid_label", "labels must be benign or malicious")

    pairs = tuple(zip(expected, predicted, strict=True))
    tn = sum(a == "benign" and p == "benign" for a, p in pairs)
    fp = sum(a == "benign" and p == "malicious" for a, p in pairs)
    fn = sum(a == "malicious" and p == "benign" for a, p in pairs)
    tp = sum(a == "malicious" and p == "malicious" for a, p in pairs)
    counts = {"benign": tn + fp, "malicious": tp + fn}
    predicted_counts = {"benign": tn + fn, "malicious": tp + fp}
    values = {
        "benign": (tn, fp, fn),
        "malicious": (tp, fn, fp),
    }
    per_class: list[ClassMetrics] = []
    f1_values: dict[str, float | None] = {}
    for label in LABELS:
        true_positive, false_negative, false_positive = values[label]
        precision = _ratio(
            true_positive,
            true_positive + false_positive,
            f"precision_{label} has no predicted observations",
        )
        recall = _ratio(
            true_positive,
            true_positive + false_negative,
            f"recall_{label} has no actual observations",
        )
        f1 = _ratio(
            2 * true_positive,
            2 * true_positive + false_positive + false_negative,
            f"f1_{label} has no actual or predicted observations",
        )
        f1_values[label] = _metric_value(f1)
        per_class.append(
            ClassMetrics(
                label=label,
                support=counts[label],
                predicted_count=predicted_counts[label],
                precision=precision,
                recall=recall,
                f1=f1,
            )
        )

    if any(value is None for value in f1_values.values()):
        macro_f1: MetricResult = _unavailable(
            "macro F1 requires defined F1 for both declared classes"
        )
        weighted_f1: MetricResult = _unavailable(
            "weighted F1 requires defined F1 for both declared classes"
        )
    else:
        benign_value = f1_values["benign"]
        malicious_value = f1_values["malicious"]
        assert benign_value is not None and malicious_value is not None
        benign_f1 = float(benign_value)
        malicious_f1 = float(malicious_value)
        macro_f1 = _available((benign_f1 + malicious_f1) / 2)
        weighted_f1 = _available(
            (benign_f1 * counts["benign"] + malicious_f1 * counts["malicious"])
            / len(expected)
        )

    false_positive_rate = _ratio(fp, tn + fp, "no actual benign observations")
    false_negative_rate = _ratio(fn, tp + fn, "no actual malicious observations")
    fpr = _metric_value(false_positive_rate)
    fnr = _metric_value(false_negative_rate)
    balanced = (
        _available(((1 - fpr) + (1 - fnr)) / 2)
        if fpr is not None and fnr is not None
        else _unavailable("balanced accuracy requires both actual classes")
    )
    return ClassificationMetrics(
        confusion_matrix=ConfusionMatrix(
            true_benign_predicted_benign=tn,
            true_benign_predicted_malicious=fp,
            true_malicious_predicted_benign=fn,
            true_malicious_predicted_malicious=tp,
        ),
        per_class=tuple(per_class),
        macro_f1=macro_f1,
        weighted_f1=weighted_f1,
        balanced_accuracy=balanced,
        false_positive_count=fp,
        false_negative_count=fn,
        false_positive_rate=false_positive_rate,
        false_negative_rate=false_negative_rate,
        correct_count=tn + tp,
    )


def _validate_probabilities(
    expected: Sequence[str], probabilities: NDArray[np.float64]
) -> None:
    if probabilities.ndim != 1 or len(probabilities) != len(expected) or not expected:
        raise EvaluationError(
            "invalid_probability_shape",
            "probabilities must align one-to-one with labels",
        )
    if not np.isfinite(probabilities).all():
        raise EvaluationError(
            "non_finite_probability", "probabilities must all be finite"
        )
    if np.any((probabilities < 0) | (probabilities > 1)):
        raise EvaluationError(
            "probability_out_of_range", "probabilities must be within [0, 1]"
        )


def calculate_probability_metrics(
    expected: Sequence[str],
    probabilities: NDArray[np.float64],
    *,
    reliability_bin_count: int,
) -> ProbabilityMetrics:
    _validate_probabilities(expected, probabilities)
    if any(value not in LABELS for value in expected):
        raise EvaluationError("invalid_label", "labels must be benign or malicious")
    binary = np.asarray([value == "malicious" for value in expected], dtype=int)
    has_both_classes = len(set(expected)) == 2
    unavailable_reason = "probability ranking requires both actual classes"
    roc_auc: MetricResult = (
        _available(float(roc_auc_score(binary, probabilities)))
        if has_both_classes
        else _unavailable(unavailable_reason)
    )
    average_precision: MetricResult = (
        _available(float(average_precision_score(binary, probabilities)))
        if has_both_classes
        else _unavailable(unavailable_reason)
    )
    bins: list[ReliabilityBin] = []
    boundaries = np.linspace(0.0, 1.0, reliability_bin_count + 1)
    for index in range(reliability_bin_count):
        lower = float(boundaries[index])
        upper = float(boundaries[index + 1])
        selected = (probabilities >= lower) & (
            probabilities <= upper
            if index == reliability_bin_count - 1
            else probabilities < upper
        )
        count = int(selected.sum())
        bins.append(
            ReliabilityBin(
                lower_bound=lower,
                upper_bound=upper,
                count=count,
                mean_predicted_probability=(
                    float(probabilities[selected].mean()) if count else None
                ),
                observed_malicious_fraction=(
                    float(binary[selected].mean()) if count else None
                ),
            )
        )
    return ProbabilityMetrics(
        source="predict_proba_malicious_column",
        roc_auc=roc_auc,
        average_precision=average_precision,
        brier_score=_available(float(brier_score_loss(binary, probabilities))),
        log_loss=_available(float(log_loss(binary, probabilities, labels=[0, 1]))),
        reliability_bins=tuple(bins),
        calibration_limitation=(
            "Reliability bins are descriptive only; no calibrator was fit and "
            "calibration was not independently evaluated."
        ),
    )


def _distribution(
    counts: dict[str, int], *, small_support: bool
) -> DistributionSummary:
    total = sum(counts.values())
    if total <= 0:
        raise EvaluationError("empty_distribution", "class distribution is empty")
    typed_counts = {
        "benign": counts.get("benign", 0),
        "malicious": counts.get("malicious", 0),
    }
    proportions = {label: typed_counts[label] / total for label in LABELS}
    majority = max(LABELS, key=lambda label: (typed_counts[label], label == "benign"))
    warnings: list[str] = []
    if typed_counts["benign"] != typed_counts["malicious"]:
        warnings.append("class_imbalance_observed")
    if small_support:
        warnings.append("small_support_exploratory_only")
    return DistributionSummary(
        counts=typed_counts,
        proportions=proportions,
        majority_class=majority,
        majority_class_baseline_accuracy=proportions[majority],
        minority_class_support=min(typed_counts.values()),
        warnings=tuple(warnings),
    )


def _threshold_results(
    expected: Sequence[str],
    probabilities: NDArray[np.float64],
    thresholds: Sequence[float],
) -> tuple[ThresholdResult, ...]:
    results: list[ThresholdResult] = []
    for threshold in thresholds:
        predicted = [
            "malicious" if probability >= threshold else "benign"
            for probability in probabilities
        ]
        metrics = calculate_classification_metrics(expected, predicted)
        malicious = metrics.per_class[1]
        results.append(
            ThresholdResult(
                threshold=threshold,
                false_positive_count=metrics.false_positive_count,
                false_negative_count=metrics.false_negative_count,
                precision_malicious=malicious.precision,
                recall_malicious=malicious.recall,
                f1_malicious=malicious.f1,
                predicted_malicious_count=malicious.predicted_count,
            )
        )
    return tuple(results)


def _entropy_band(value: float) -> str:
    if value <= 3:
        return "low_0_to_3"
    if value <= 6:
        return "medium_over_3_to_6"
    return "high_over_6_to_8"


def _error_analysis(
    records: Sequence[MLDatasetRecord],
    expected: Sequence[str],
    predicted: Sequence[str],
) -> ErrorAnalysis:
    groups: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0, 0])
    for record, actual, guess in zip(records, expected, predicted, strict=True):
        dimensions = (
            ("detected_format", record.features.detected_format),
            ("entropy_band", _entropy_band(record.features.shannon_entropy)),
            ("has_indicators", str(record.features.indicator_count > 0).lower()),
        )
        for dimension, value in dimensions:
            counters = groups[(dimension, value)]
            counters[0] += 1
            counters[1] += actual == "benign" and guess == "malicious"
            counters[2] += actual == "malicious" and guess == "benign"
    subgroups = tuple(
        ErrorSubgroup(
            dimension=dimension,
            value=value,
            support=values[0],
            false_positive_count=values[1],
            false_negative_count=values[2],
            warning="small_subgroup_no_generalization" if values[0] < 5 else None,
        )
        for (dimension, value), values in sorted(groups.items())
    )
    metrics = calculate_classification_metrics(expected, predicted)
    return ErrorAnalysis(
        correct_count=metrics.correct_count,
        false_positive_count=metrics.false_positive_count,
        false_negative_count=metrics.false_negative_count,
        subgroups=subgroups,
    )


def _probability_column(
    pipeline: Pipeline, matrix: NDArray[np.object_]
) -> NDArray[np.float64] | None:
    if not hasattr(pipeline, "predict_proba"):
        return None
    classes = [str(value) for value in pipeline.classes_]
    if "malicious" not in classes:
        raise EvaluationError(
            "positive_class_missing", "model probability classes omit malicious"
        )
    raw = np.asarray(pipeline.predict_proba(matrix), dtype=float)
    if raw.ndim != 2 or raw.shape != (len(matrix), len(classes)):
        raise EvaluationError(
            "invalid_probability_shape", "predict_proba returned an invalid shape"
        )
    return np.asarray(raw[:, classes.index("malicious")], dtype=np.float64)


def _feature_influences(
    pipeline: Pipeline,
    matrix: NDArray[np.object_],
    labels: NDArray[np.str_],
    configuration: EvaluationConfiguration,
) -> tuple[FeatureInfluence, ...]:
    result = permutation_importance(
        pipeline,
        matrix,
        labels,
        scoring="f1_macro",
        n_repeats=configuration.permutation_repeats,
        random_state=configuration.random_seed,
        n_jobs=1,
    )
    if len(result.importances_mean) != len(PREDICTIVE_FEATURE_ORDER):
        raise EvaluationError(
            "feature_importance_shape", "permutation importance violated feature order"
        )
    return tuple(
        FeatureInfluence(
            feature=feature,
            mean_importance=float(result.importances_mean[index]),
            standard_deviation=float(result.importances_std[index]),
            repeats=configuration.permutation_repeats,
        )
        for index, feature in enumerate(PREDICTIVE_FEATURE_ORDER)
    )


def _comparison(
    reports: Sequence[ModelEvaluationReport], support: int
) -> tuple[ModelComparison, ...]:
    values: list[ModelComparison] = []
    for report in sorted(reports, key=lambda item: item.algorithm):
        probability = report.probability
        values.append(
            ModelComparison(
                algorithm=report.algorithm,
                macro_f1=report.classification.macro_f1,
                malicious_recall=report.classification.per_class[1].recall,
                false_positive_rate=report.classification.false_positive_rate,
                balanced_accuracy=report.classification.balanced_accuracy,
                average_precision=(
                    probability.average_precision
                    if probability is not None
                    else _unavailable(
                        report.probability_unavailable_reason or "unavailable"
                    )
                ),
                validation_support=support,
            )
        )
    return tuple(values)


def select_candidate(
    comparison: Sequence[ModelComparison],
    *,
    mode: str,
    configuration: EvaluationConfiguration,
) -> ModelSelectionDecision:
    if mode == "synthetic_demo":
        return ModelSelectionDecision(
            status="insufficient_evidence",
            selected_candidate=None,
            reason_code="synthetic_evidence",
            rationale="Synthetic smoke-test results cannot authorize model selection.",
        )
    if not comparison:
        return ModelSelectionDecision(
            status="validation_failure",
            selected_candidate=None,
            reason_code="no_candidates",
            rationale="No candidate evaluations were available.",
        )
    if (
        min(item.validation_support for item in comparison)
        < configuration.minimum_selection_support
    ):
        return ModelSelectionDecision(
            status="insufficient_evidence",
            selected_candidate=None,
            reason_code="operational_support_policy",
            rationale=(
                "Validation support is below the predeclared operational selection "
                "policy; this is not a scientific sample-size claim."
            ),
        )
    if any(not item.macro_f1.available for item in comparison):
        return ModelSelectionDecision(
            status="validation_failure",
            selected_candidate=None,
            reason_code="primary_metric_unavailable",
            rationale="Macro F1 is unavailable for one or more candidates.",
        )
    ranked = sorted(
        comparison,
        key=lambda item: (-_required_metric_value(item.macro_f1), item.algorithm),
    )
    best, runner_up = ranked[:2]
    margin = _required_metric_value(best.macro_f1) - _required_metric_value(
        runner_up.macro_f1
    )
    if margin < configuration.minimum_primary_metric_margin:
        return ModelSelectionDecision(
            status="inconclusive_performance",
            selected_candidate=None,
            reason_code="primary_metric_tie_or_small_margin",
            rationale="The primary-metric difference is too small for selection.",
        )
    malicious_recall = _metric_value(best.malicious_recall)
    if (
        malicious_recall is None
        or malicious_recall < configuration.minimum_malicious_recall
    ):
        return ModelSelectionDecision(
            status="insufficient_evidence",
            selected_candidate=None,
            reason_code="minimum_quality_not_met",
            rationale="The leading candidate does not meet the declared recall floor.",
        )
    return ModelSelectionDecision(
        status="selected",
        selected_candidate=best.algorithm,
        reason_code="policy_requirements_met",
        rationale=(
            "The candidate leads macro F1 by the required margin and meets the "
            "declared malicious-recall floor on this research validation set."
        ),
    )


def _verify_compatibility(
    trained: TrainedExperiment,
    manifest: DatasetManifest,
    records: Sequence[MLDatasetRecord],
) -> None:
    report = trained.report
    if not verify_dataset_integrity(manifest, records):
        raise EvaluationError(
            "dataset_integrity_failed", "dataset integrity is invalid"
        )
    if (
        report.dataset_id != manifest.dataset_id
        or report.dataset_version != manifest.dataset_version
        or report.dataset_integrity_digest != manifest.content_integrity_digest
    ):
        raise EvaluationError(
            "dataset_identity_mismatch", "experiment and dataset identity differ"
        )
    if report.feature_schema_version != manifest.feature_schema_version:
        raise EvaluationError(
            "feature_schema_mismatch", "experiment and dataset feature schemas differ"
        )
    expected_algorithms = {item.algorithm for item in report.models}
    if set(trained.pipelines) != expected_algorithms:
        raise EvaluationError(
            "model_set_mismatch", "in-process pipelines do not match the experiment"
        )


def evaluate_experiment(
    trained: TrainedExperiment,
    manifest: DatasetManifest,
    records: Sequence[MLDatasetRecord],
    *,
    evaluation_id: str,
    configuration: EvaluationConfiguration | None = None,
    evaluated_at: datetime | None = None,
) -> EvaluatedExperiment:
    if re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", evaluation_id) is None:
        raise EvaluationError(
            "invalid_evaluation_id", "evaluation ID is not a safe path component"
        )
    configuration = configuration or EvaluationConfiguration(
        random_seed=trained.configuration.random_seed
    )
    _verify_compatibility(trained, manifest, records)
    validation = tuple(record for record in records if record.split == "validation")
    if not validation:
        raise EvaluationError("empty_validation", "validation partition is empty")
    if len(validation) > configuration.maximum_evaluated_samples:
        raise EvaluationError(
            "evaluation_too_large", "validation exceeds the configured sample limit"
        )
    matrix = build_feature_matrix(validation)
    labels_array = build_labels(validation)
    expected = [str(value) for value in labels_array]
    model_configs = {
        item.algorithm: item.hyperparameters for item in trained.report.models
    }
    model_reports: list[ModelEvaluationReport] = []
    for algorithm in sorted(trained.pipelines):
        pipeline = trained.pipelines[algorithm]
        predicted_array = np.asarray(pipeline.predict(matrix), dtype=str)
        predicted = [str(value) for value in predicted_array]
        classification = calculate_classification_metrics(expected, predicted)
        probabilities = _probability_column(pipeline, matrix)
        probability = (
            calculate_probability_metrics(
                expected,
                probabilities,
                reliability_bin_count=configuration.reliability_bin_count,
            )
            if probabilities is not None
            else None
        )
        warnings: list[str] = []
        if len(validation) < configuration.minimum_selection_support:
            warnings.append("small_validation_support_exploratory_only")
        model_reports.append(
            ModelEvaluationReport(
                algorithm=algorithm,
                hyperparameters=model_configs[algorithm],
                classification=classification,
                probability=probability,
                probability_unavailable_reason=(
                    None if probability is not None else "model has no predict_proba"
                ),
                thresholds=(
                    _threshold_results(
                        expected, probabilities, configuration.threshold_candidates
                    )
                    if probabilities is not None
                    else ()
                ),
                error_analysis=_error_analysis(validation, expected, predicted),
                feature_influences=_feature_influences(
                    pipeline, matrix, labels_array, configuration
                ),
                explainability_method="permutation_importance_original_features",
                explainability_scoring="f1_macro",
                warnings=tuple(warnings),
            )
        )
    comparison = _comparison(model_reports, len(validation))
    selection = select_candidate(
        comparison,
        mode=trained.report.mode,
        configuration=configuration,
    )
    validation_counts = Counter(expected)
    limitations = EvaluationLimitations(
        exploratory_only=(
            trained.report.mode == "synthetic_demo"
            or len(validation) < configuration.minimum_selection_support
        ),
        statements=(
            "Validation estimates do not constitute final test performance.",
            "Model probability is not a calibrated confidence or security risk score.",
            "Permutation importance is model- and dataset-specific, not causal.",
            "Correlated features can divide or mask permutation importance.",
            "Local feature-contribution narratives are not implemented.",
        ),
    )
    report = EvaluationReport(
        evaluation_id=evaluation_id,
        experiment_id=trained.report.experiment_id,
        experiment_schema_version=trained.report.experiment_schema_version,
        dataset_id=manifest.dataset_id,
        dataset_version=manifest.dataset_version,
        dataset_integrity_digest=manifest.content_integrity_digest,
        feature_schema_version=manifest.feature_schema_version,
        mode=trained.report.mode,
        validation_record_count=len(validation),
        training_distribution=_distribution(
            trained.report.training_class_distribution,
            small_support=trained.report.training_record_count
            < configuration.minimum_selection_support,
        ),
        validation_distribution=_distribution(
            dict(validation_counts),
            small_support=len(validation) < configuration.minimum_selection_support,
        ),
        random_seed=configuration.random_seed,
        permutation_repeats=configuration.permutation_repeats,
        evaluated_at=evaluated_at or datetime.now(UTC),
        models=tuple(model_reports),
        comparison=comparison,
        selection=selection,
        limitations=limitations,
    )
    return EvaluatedExperiment(report=report, configuration=configuration)
