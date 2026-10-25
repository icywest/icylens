from datetime import datetime, timedelta
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas.ml_experiment import (
    ExperimentMode,
    ExperimentSchemaVersion,
    JsonScalar,
    ModelAlgorithm,
)
from app.schemas.ml_features import FeatureSchemaVersion, PredictiveFeatureName

EvaluationSchemaVersion = Literal["1.0.0"]
EVALUATION_SCHEMA_VERSION: EvaluationSchemaVersion = "1.0.0"
LabelName = Literal["benign", "malicious"]
SelectionStatus = Literal[
    "selected",
    "insufficient_evidence",
    "inconclusive_performance",
    "validation_failure",
]


class AvailableMetric(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    available: Literal[True] = True
    value: float
    reason: None = None


class UnavailableMetric(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    available: Literal[False] = False
    value: None = None
    reason: Annotated[str, Field(min_length=1, max_length=256)]


MetricResult = AvailableMetric | UnavailableMetric


class EvaluationConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    random_seed: Annotated[int, Field(ge=0, le=2**32 - 1)] = 42
    permutation_repeats: Annotated[int, Field(ge=1, le=20)] = 5
    maximum_evaluated_samples: Annotated[int, Field(ge=2, le=100_000)] = 10_000
    reliability_bin_count: Annotated[int, Field(ge=2, le=20)] = 5
    threshold_candidates: tuple[Annotated[float, Field(gt=0, lt=1)], ...] = (
        0.3,
        0.5,
        0.7,
    )
    minimum_selection_support: Annotated[int, Field(ge=2, le=100_000)] = 100
    minimum_primary_metric_margin: Annotated[float, Field(ge=0, le=1)] = 0.02
    minimum_malicious_recall: Annotated[float, Field(ge=0, le=1)] = 0.5

    @field_validator("threshold_candidates")
    @classmethod
    def validate_thresholds(cls, value: tuple[float, ...]) -> tuple[float, ...]:
        if not value or len(value) > 21:
            raise ValueError("threshold candidates require between 1 and 21 values")
        if tuple(sorted(set(value))) != value:
            raise ValueError("threshold candidates must be unique and sorted")
        return value


class ConfusionMatrix(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    label_order: tuple[LabelName, LabelName] = ("benign", "malicious")
    true_benign_predicted_benign: Annotated[int, Field(ge=0)]
    true_benign_predicted_malicious: Annotated[int, Field(ge=0)]
    true_malicious_predicted_benign: Annotated[int, Field(ge=0)]
    true_malicious_predicted_malicious: Annotated[int, Field(ge=0)]


class ClassMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    label: LabelName
    support: Annotated[int, Field(ge=0)]
    predicted_count: Annotated[int, Field(ge=0)]
    precision: MetricResult = Field(discriminator="available")
    recall: MetricResult = Field(discriminator="available")
    f1: MetricResult = Field(discriminator="available")


class ClassificationMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    confusion_matrix: ConfusionMatrix
    per_class: tuple[ClassMetrics, ClassMetrics]
    macro_f1: MetricResult = Field(discriminator="available")
    weighted_f1: MetricResult = Field(discriminator="available")
    balanced_accuracy: MetricResult = Field(discriminator="available")
    false_positive_count: Annotated[int, Field(ge=0)]
    false_negative_count: Annotated[int, Field(ge=0)]
    false_positive_rate: MetricResult = Field(discriminator="available")
    false_negative_rate: MetricResult = Field(discriminator="available")
    correct_count: Annotated[int, Field(ge=0)]

    @model_validator(mode="after")
    def validate_class_order(self) -> Self:
        if tuple(item.label for item in self.per_class) != ("benign", "malicious"):
            raise ValueError("per-class metrics must use benign, malicious order")
        return self


class ReliabilityBin(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    lower_bound: Annotated[float, Field(ge=0, le=1)]
    upper_bound: Annotated[float, Field(ge=0, le=1)]
    count: Annotated[int, Field(ge=0)]
    mean_predicted_probability: Annotated[float, Field(ge=0, le=1)] | None
    observed_malicious_fraction: Annotated[float, Field(ge=0, le=1)] | None


class ProbabilityMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source: Literal["predict_proba_malicious_column"]
    positive_class: Literal["malicious"] = "malicious"
    roc_auc: MetricResult = Field(discriminator="available")
    average_precision: MetricResult = Field(discriminator="available")
    brier_score: MetricResult = Field(discriminator="available")
    log_loss: MetricResult = Field(discriminator="available")
    reliability_bins: tuple[ReliabilityBin, ...]
    calibration_status: Literal["not_established"] = "not_established"
    calibration_limitation: str


class ThresholdResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    threshold: Annotated[float, Field(gt=0, lt=1)]
    false_positive_count: Annotated[int, Field(ge=0)]
    false_negative_count: Annotated[int, Field(ge=0)]
    precision_malicious: MetricResult = Field(discriminator="available")
    recall_malicious: MetricResult = Field(discriminator="available")
    f1_malicious: MetricResult = Field(discriminator="available")
    predicted_malicious_count: Annotated[int, Field(ge=0)]


class DistributionSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    counts: dict[LabelName, Annotated[int, Field(ge=0)]]
    proportions: dict[LabelName, Annotated[float, Field(ge=0, le=1)]]
    majority_class: LabelName
    majority_class_baseline_accuracy: Annotated[float, Field(ge=0, le=1)]
    minority_class_support: Annotated[int, Field(ge=0)]
    warnings: tuple[str, ...]


class ErrorSubgroup(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    dimension: Literal["detected_format", "entropy_band", "has_indicators"]
    value: Annotated[str, Field(min_length=1, max_length=64)]
    support: Annotated[int, Field(ge=1)]
    false_positive_count: Annotated[int, Field(ge=0)]
    false_negative_count: Annotated[int, Field(ge=0)]
    warning: str | None = None


class ErrorAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    correct_count: Annotated[int, Field(ge=0)]
    false_positive_count: Annotated[int, Field(ge=0)]
    false_negative_count: Annotated[int, Field(ge=0)]
    subgroups: tuple[ErrorSubgroup, ...]
    privacy_note: Literal[
        "aggregate-only; no hashes, filenames, strings, or sample content"
    ] = "aggregate-only; no hashes, filenames, strings, or sample content"


class FeatureInfluence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    feature: PredictiveFeatureName
    mean_importance: float
    standard_deviation: Annotated[float, Field(ge=0)]
    repeats: Annotated[int, Field(ge=1, le=20)]


class ModelEvaluationReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    algorithm: ModelAlgorithm
    hyperparameters: dict[str, JsonScalar]
    classification: ClassificationMetrics
    probability: ProbabilityMetrics | None
    probability_unavailable_reason: str | None
    thresholds: tuple[ThresholdResult, ...]
    error_analysis: ErrorAnalysis
    feature_influences: tuple[FeatureInfluence, ...]
    explainability_method: Literal["permutation_importance_original_features"]
    explainability_scoring: Literal["f1_macro"]
    warnings: tuple[str, ...]

    @model_validator(mode="after")
    def validate_probability_state(self) -> Self:
        if (self.probability is None) == (self.probability_unavailable_reason is None):
            raise ValueError("probability availability requires exactly one state")
        if self.probability is None and self.thresholds:
            raise ValueError("thresholds require probability estimates")
        return self


class ModelComparison(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    algorithm: ModelAlgorithm
    macro_f1: MetricResult = Field(discriminator="available")
    malicious_recall: MetricResult = Field(discriminator="available")
    false_positive_rate: MetricResult = Field(discriminator="available")
    balanced_accuracy: MetricResult = Field(discriminator="available")
    average_precision: MetricResult = Field(discriminator="available")
    validation_support: Annotated[int, Field(ge=0)]


class ModelSelectionDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: SelectionStatus
    selected_candidate: ModelAlgorithm | None
    primary_metric: Literal["macro_f1"] = "macro_f1"
    reason_code: str
    rationale: str

    @model_validator(mode="after")
    def validate_selection(self) -> Self:
        if (self.status == "selected") != (self.selected_candidate is not None):
            raise ValueError("only selected status may name a candidate")
        return self


class EvaluationLimitations(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    exploratory_only: bool
    scientific_representativeness: Literal["not_established"] = "not_established"
    calibration_status: Literal["not_established"] = "not_established"
    local_explanations_status: Literal["not_implemented"] = "not_implemented"
    statements: tuple[str, ...]


class EvaluationReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    evaluation_schema_version: EvaluationSchemaVersion = EVALUATION_SCHEMA_VERSION
    evaluation_id: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")]
    experiment_id: str
    experiment_schema_version: ExperimentSchemaVersion
    metric_definitions_version: Literal["binary-malware-metrics/1.0.0"] = (
        "binary-malware-metrics/1.0.0"
    )
    dataset_id: str
    dataset_version: str
    dataset_integrity_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    feature_schema_version: FeatureSchemaVersion
    mode: ExperimentMode
    evaluated_split: Literal["validation"] = "validation"
    label_order: tuple[LabelName, LabelName] = ("benign", "malicious")
    negative_class: Literal["benign"] = "benign"
    positive_class: Literal["malicious"] = "malicious"
    validation_record_count: Annotated[int, Field(gt=0)]
    training_distribution: DistributionSummary
    validation_distribution: DistributionSummary
    random_seed: int
    permutation_repeats: Annotated[int, Field(ge=1, le=20)]
    evaluated_at: datetime
    test_set_accessed: Literal[False] = False
    models: tuple[ModelEvaluationReport, ...]
    comparison: tuple[ModelComparison, ...]
    selection: ModelSelectionDecision
    limitations: EvaluationLimitations

    @field_validator("evaluated_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("evaluated_at must be timezone-aware UTC")
        return value

    @model_validator(mode="after")
    def validate_model_sets(self) -> Self:
        expected = {
            "logistic_regression",
            "random_forest",
            "hist_gradient_boosting",
        }
        models = {item.algorithm for item in self.models}
        comparisons = {item.algorithm for item in self.comparison}
        if models != expected or comparisons != expected:
            raise ValueError("evaluation requires the three baseline candidates")
        if len(self.models) != 3 or len(self.comparison) != 3:
            raise ValueError("evaluation candidates must be unique")
        return self


class EvaluationArtifactManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    report: EvaluationReport
    report_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    report_size_bytes: Annotated[int, Field(gt=0)]
    serialization: Literal["utf8-canonical-json"] = "utf8-canonical-json"
