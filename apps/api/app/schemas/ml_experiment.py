from datetime import datetime, timedelta
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas.ml_features import FEATURE_SCHEMA_VERSION, FeatureSchemaVersion

ExperimentSchemaVersion = Literal["1.0.0"]
TrainingPipelineVersion = Literal["training-pipeline/1.0.0"]
EXPERIMENT_SCHEMA_VERSION: ExperimentSchemaVersion = "1.0.0"
TRAINING_PIPELINE_VERSION: TrainingPipelineVersion = "training-pipeline/1.0.0"

ModelAlgorithm = Literal[
    "logistic_regression",
    "random_forest",
    "hist_gradient_boosting",
]
ExperimentMode = Literal["synthetic_demo", "research_evaluation"]
JsonScalar = str | int | float | bool | None


class LogisticRegressionConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    maximum_iterations: Annotated[int, Field(ge=50, le=5000)] = 300
    regularization_c: Annotated[float, Field(gt=0, le=100)] = 1.0
    class_weight: Literal["balanced"] | None = None


class RandomForestConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    estimator_count: Annotated[int, Field(ge=10, le=500)] = 100
    maximum_depth: Annotated[int, Field(ge=1, le=100)] | None = None
    minimum_samples_per_leaf: Annotated[int, Field(ge=1, le=100)] = 1
    class_weight: Literal["balanced"] | None = None
    parallel_jobs: Literal[1] = 1


class HistGradientBoostingConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    learning_rate: Annotated[float, Field(gt=0, le=1)] = 0.1
    maximum_iterations: Annotated[int, Field(ge=10, le=500)] = 100
    maximum_leaf_nodes: Annotated[int, Field(ge=2, le=255)] = 31
    minimum_samples_per_leaf: Annotated[int, Field(ge=1, le=1000)] = 5


class TrainingConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    random_seed: Annotated[int, Field(ge=0, le=2**32 - 1)] = 42
    maximum_dataset_records: Annotated[int, Field(ge=6, le=100_000)] = 10_000
    maximum_transformed_features: Annotated[int, Field(ge=14, le=1024)] = 64
    maximum_model_artifact_bytes: Annotated[
        int, Field(ge=1024, le=1024 * 1024 * 1024)
    ] = 100 * 1024 * 1024
    minimum_training_records_per_class: Annotated[int, Field(ge=2, le=1000)] = 2
    minimum_validation_records_per_class: Annotated[int, Field(ge=1, le=1000)] = 1
    feature_schema_version: FeatureSchemaVersion = FEATURE_SCHEMA_VERSION
    logistic_regression: LogisticRegressionConfiguration = (
        LogisticRegressionConfiguration()
    )
    random_forest: RandomForestConfiguration = RandomForestConfiguration()
    hist_gradient_boosting: HistGradientBoostingConfiguration = (
        HistGradientBoostingConfiguration()
    )


class PreprocessingConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    input_feature_count: Literal[14] = 14
    transformed_feature_count: Annotated[int, Field(ge=14)]
    numeric_features: tuple[str, ...]
    categorical_features: tuple[str, ...]
    boolean_features: tuple[str, ...]
    categorical_encoding: Literal["one_hot_explicit_categories"] = (
        "one_hot_explicit_categories"
    )
    unknown_category_policy: Literal["ignore_to_all_zero"] = "ignore_to_all_zero"
    logistic_numeric_scaling: Literal["standard_scaler"] = "standard_scaler"
    tree_numeric_scaling: Literal["passthrough"] = "passthrough"
    fit_partition: Literal["training"] = "training"


class ValidationMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    confusion_matrix: tuple[tuple[int, int], tuple[int, int]]
    precision_malicious: Annotated[float, Field(ge=0, le=1)]
    recall_malicious: Annotated[float, Field(ge=0, le=1)]
    f1_malicious: Annotated[float, Field(ge=0, le=1)]
    balanced_accuracy: Annotated[float, Field(ge=0, le=1)]
    validation_support: dict[str, Annotated[int, Field(ge=0)]]
    prediction_counts: dict[str, Annotated[int, Field(ge=0)]]
    undefined_metrics: tuple[str, ...]


class ModelRunReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    algorithm: ModelAlgorithm
    hyperparameters: dict[str, JsonScalar]
    validation_metrics: ValidationMetrics


class ExperimentReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    experiment_schema_version: ExperimentSchemaVersion = EXPERIMENT_SCHEMA_VERSION
    training_pipeline_version: TrainingPipelineVersion = TRAINING_PIPELINE_VERSION
    experiment_id: Annotated[
        str,
        Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$"),
    ]
    mode: ExperimentMode
    scientific_representativeness: Literal["not_established"] = "not_established"
    dataset_id: str
    dataset_version: str
    dataset_integrity_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    feature_schema_version: FeatureSchemaVersion
    extraction_versions: tuple[str, ...]
    random_seed: int
    python_version: str
    numpy_version: str
    scikit_learn_version: str
    joblib_version: str
    preprocessing: PreprocessingConfiguration
    training_record_count: Annotated[int, Field(gt=0)]
    validation_record_count: Annotated[int, Field(gt=0)]
    training_class_distribution: dict[str, Annotated[int, Field(ge=0)]]
    validation_class_distribution: dict[str, Annotated[int, Field(ge=0)]]
    test_set_accessed: Literal[False] = False
    created_at: datetime
    models: tuple[ModelRunReport, ...]

    @field_validator("created_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        if value.utcoffset() != timedelta(0):
            raise ValueError("created_at must use UTC")
        return value

    @model_validator(mode="after")
    def validate_model_set(self) -> Self:
        algorithms = {model.algorithm for model in self.models}
        if algorithms != {
            "logistic_regression",
            "random_forest",
            "hist_gradient_boosting",
        }:
            raise ValueError(
                "experiment must contain exactly the three baseline models"
            )
        if len(self.models) != 3:
            raise ValueError("experiment model reports must be unique")
        return self


class ModelArtifactDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    algorithm: ModelAlgorithm
    relative_path: Annotated[
        str,
        Field(pattern=r"^models/[a-z_]+\.joblib$"),
    ]
    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    size_bytes: Annotated[int, Field(gt=0)]
    serialization: Literal["joblib-pickle-local-trusted-only"] = (
        "joblib-pickle-local-trusted-only"
    )


class ExperimentManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    report: ExperimentReport
    model_artifacts: tuple[ModelArtifactDescriptor, ...]

    @model_validator(mode="after")
    def validate_artifact_set(self) -> Self:
        report_algorithms = {model.algorithm for model in self.report.models}
        artifact_algorithms = {item.algorithm for item in self.model_artifacts}
        if report_algorithms != artifact_algorithms or len(self.model_artifacts) != 3:
            raise ValueError("model artifacts must match experiment model reports")
        return self
