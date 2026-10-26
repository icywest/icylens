from dataclasses import dataclass
from typing import cast

import numpy as np
from sklearn.compose import ColumnTransformer  # type: ignore[import-untyped]
from sklearn.ensemble import (  # type: ignore[import-untyped]
    HistGradientBoostingClassifier,
    RandomForestClassifier,
)
from sklearn.exceptions import NotFittedError  # type: ignore[import-untyped]
from sklearn.linear_model import LogisticRegression  # type: ignore[import-untyped]
from sklearn.pipeline import Pipeline  # type: ignore[import-untyped]
from sklearn.utils.validation import check_is_fitted  # type: ignore[import-untyped]

from app.ml.preprocessing import (
    TRANSFORMED_FEATURE_COUNT,
    build_feature_row,
    expected_transformed_feature_names,
    preprocessing_configuration,
    transformed_feature_names,
)
from app.schemas.ml_features import FEATURE_SCHEMA_VERSION, MLFeatureVector
from app.schemas.ml_inference import (
    ActiveModelDescriptor,
    ClassProbabilities,
    InferenceLabel,
    ModelLifecycleStatus,
)

SUPPORTED_MODEL_TYPES = {
    "logistic_regression": LogisticRegression,
    "random_forest": RandomForestClassifier,
    "hist_gradient_boosting": HistGradientBoostingClassifier,
}
EXPECTED_CLASSES = ("benign", "malicious")


class ModelRuntimeError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class TrustedPrediction:
    label: InferenceLabel
    probabilities: ClassProbabilities


def validate_trusted_pipeline(
    pipeline: Pipeline,
    descriptor: ActiveModelDescriptor,
) -> None:
    if descriptor.feature_schema_version != FEATURE_SCHEMA_VERSION:
        raise ModelRuntimeError(
            "feature_schema_mismatch", "model feature schema is unsupported"
        )
    if descriptor.preprocessing != preprocessing_configuration():
        raise ModelRuntimeError(
            "preprocessing_mismatch", "model preprocessing contract is incompatible"
        )
    if tuple(pipeline.named_steps) != ("preprocessing", "model"):
        raise ModelRuntimeError(
            "invalid_pipeline_structure", "trusted Pipeline steps are incompatible"
        )
    preprocessor = pipeline.named_steps["preprocessing"]
    if not isinstance(preprocessor, ColumnTransformer):
        raise ModelRuntimeError(
            "preprocessing_mismatch", "Pipeline lacks the required ColumnTransformer"
        )
    expected_model_type = SUPPORTED_MODEL_TYPES.get(descriptor.algorithm)
    if expected_model_type is None:
        raise ModelRuntimeError(
            "unsupported_algorithm", "descriptor algorithm is unsupported"
        )
    if not isinstance(pipeline.named_steps["model"], expected_model_type):
        raise ModelRuntimeError(
            "algorithm_mismatch", "descriptor algorithm does not match estimator"
        )
    try:
        check_is_fitted(pipeline)
    except (NotFittedError, TypeError) as error:
        raise ModelRuntimeError(
            "model_not_fitted", "Pipeline must be fitted before registration"
        ) from error
    names = transformed_feature_names(pipeline)
    if len(names) != descriptor.preprocessing.transformed_feature_count:
        raise ModelRuntimeError(
            "transformed_feature_mismatch",
            "fitted transformation width differs from the descriptor",
        )
    if len(names) != TRANSFORMED_FEATURE_COUNT:
        raise ModelRuntimeError(
            "transformed_feature_mismatch",
            "fitted transformation width is not supported",
        )
    if names != expected_transformed_feature_names():
        raise ModelRuntimeError(
            "transformed_feature_mismatch",
            "fitted transformed feature names are incompatible",
        )
    classes = tuple(str(value) for value in pipeline.classes_)
    if set(classes) != set(EXPECTED_CLASSES) or len(classes) != 2:
        raise ModelRuntimeError(
            "unsupported_model_classes", "model classes must be benign and malicious"
        )
    if not callable(getattr(pipeline, "predict_proba", None)):
        raise ModelRuntimeError(
            "probability_unavailable", "registered model must expose predict_proba"
        )
    if not descriptor.synthetic_data or not descriptor.demonstration_authorized:
        raise ModelRuntimeError(
            "demo_not_authorized",
            "synthetic demonstration must be explicitly authorized",
        )


class TrustedModelRuntime:
    """One explicitly registered in-process Pipeline; never a serialized loader."""

    def __init__(self) -> None:
        self._pipeline: Pipeline | None = None
        self._descriptor: ActiveModelDescriptor | None = None
        self._status: ModelLifecycleStatus = "unavailable"
        self._history: list[ModelLifecycleStatus] = ["unavailable"]

    @property
    def status(self) -> ModelLifecycleStatus:
        return self._status

    @property
    def active_descriptor(self) -> ActiveModelDescriptor | None:
        return self._descriptor

    @property
    def lifecycle_history(self) -> tuple[ModelLifecycleStatus, ...]:
        return tuple(self._history)

    def _set_status(self, status: ModelLifecycleStatus) -> None:
        self._status = status
        if self._history[-1] != status:
            self._history.append(status)

    def mark_trained(self) -> None:
        self._set_status("trained")

    def mark_evaluated(self) -> None:
        if self._status != "trained":
            raise ModelRuntimeError(
                "invalid_lifecycle_transition",
                "evaluation status requires a trained in-memory model",
            )
        self._set_status("evaluated")

    def register(
        self, pipeline: Pipeline, descriptor: ActiveModelDescriptor
    ) -> ActiveModelDescriptor:
        try:
            validate_trusted_pipeline(pipeline, descriptor)
        except Exception:
            self._pipeline = None
            self._descriptor = None
            self._set_status("rejected")
            raise
        self._pipeline = pipeline
        self._descriptor = descriptor
        self._set_status("registered_demo")
        return descriptor

    def revoke(self) -> None:
        self._pipeline = None
        self._descriptor = None
        self._set_status("revoked")

    def reject(self) -> None:
        self._pipeline = None
        self._descriptor = None
        self._set_status("rejected")

    def require_active(self) -> tuple[Pipeline, ActiveModelDescriptor]:
        if self._pipeline is None or self._descriptor is None:
            raise ModelRuntimeError(
                "model_unavailable", "no trusted demonstration model is active"
            )
        return self._pipeline, self._descriptor

    def predict(self, features: MLFeatureVector) -> TrustedPrediction:
        pipeline, _ = self.require_active()
        if features.feature_schema_version != FEATURE_SCHEMA_VERSION:
            raise ModelRuntimeError(
                "feature_schema_mismatch", "inference features are incompatible"
            )
        matrix = np.asarray([build_feature_row(features)], dtype=object)
        if matrix.shape != (1, 14):
            raise ModelRuntimeError(
                "feature_contract_mismatch", "inference requires exactly 14 features"
            )
        predicted = np.asarray(pipeline.predict(matrix))
        raw_probabilities = np.asarray(pipeline.predict_proba(matrix), dtype=float)
        classes = tuple(str(value) for value in pipeline.classes_)
        if predicted.shape != (1,) or str(predicted[0]) not in EXPECTED_CLASSES:
            raise ModelRuntimeError(
                "invalid_prediction", "model returned an unsupported prediction"
            )
        if raw_probabilities.shape != (1, 2):
            raise ModelRuntimeError(
                "invalid_probability_shape",
                "model returned an invalid probability shape",
            )
        if not np.isfinite(raw_probabilities).all():
            raise ModelRuntimeError(
                "non_finite_probability", "model returned non-finite probabilities"
            )
        if np.any((raw_probabilities < 0) | (raw_probabilities > 1)):
            raise ModelRuntimeError(
                "probability_out_of_range", "model probabilities are outside [0, 1]"
            )
        probability_sum = float(raw_probabilities[0].sum())
        if abs(probability_sum - 1.0) > 1e-9:
            raise ModelRuntimeError(
                "invalid_probability_sum", "binary probabilities do not sum to one"
            )
        mapped = {
            label: float(raw_probabilities[0, index])
            for index, label in enumerate(classes)
        }
        predicted_label = str(predicted[0])
        maximum_label = classes[int(np.argmax(raw_probabilities[0]))]
        if predicted_label != maximum_label:
            raise ModelRuntimeError(
                "probability_class_mismatch",
                "prediction and probability class ordering are inconsistent",
            )
        return TrustedPrediction(
            label=cast(InferenceLabel, predicted_label),
            probabilities=ClassProbabilities(
                benign=mapped["benign"],
                malicious=mapped["malicious"],
            ),
        )
