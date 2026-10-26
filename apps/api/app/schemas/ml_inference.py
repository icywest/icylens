from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.ml_experiment import ModelAlgorithm, PreprocessingConfiguration
from app.schemas.ml_features import FeatureSchemaVersion

InferenceMode = Literal["synthetic_demo"]
InferenceLabel = Literal["benign", "malicious"]
ModelLifecycleStatus = Literal[
    "unavailable",
    "trained",
    "evaluated",
    "registered_demo",
    "rejected",
    "revoked",
]


class ClassProbabilities(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    benign: Annotated[float, Field(ge=0, le=1)]
    malicious: Annotated[float, Field(ge=0, le=1)]

    @model_validator(mode="after")
    def require_probability_sum(self) -> Self:
        if abs((self.benign + self.malicious) - 1.0) > 1e-9:
            raise ValueError("binary probabilities must sum to one")
        return self


class InferencePrediction(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    label: InferenceLabel
    probability_estimates: ClassProbabilities
    probability_calibrated: Literal[False] = False
    interpretation: Literal["model_output_not_security_verdict"] = (
        "model_output_not_security_verdict"
    )


class ActiveModelDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    model_id: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")]
    algorithm: ModelAlgorithm
    experiment_id: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")]
    feature_schema_version: FeatureSchemaVersion
    preprocessing: PreprocessingConfiguration
    dataset_id: Annotated[str, Field(min_length=1, max_length=128)]
    dataset_integrity_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    dataset_provenance_type: Literal["synthetic"]
    evaluation_status: Literal["synthetic_validation_only"]
    model_selection_status: Literal["not_selected"] = "not_selected"
    synthetic_data: Literal[True] = True
    demonstration_authorized: Literal[True] = True
    initialization_status: Literal["ready"] = "ready"
    lifecycle_status: Literal["registered_demo"] = "registered_demo"
    operational_detection_approved: Literal[False] = False


class InferenceModelSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    model_id: str
    algorithm: ModelAlgorithm
    experiment_id: str
    feature_schema_version: FeatureSchemaVersion
    dataset_id: str
    dataset_integrity_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    dataset_provenance_type: Literal["synthetic"]
    evaluation_status: Literal["synthetic_validation_only"]
    model_selection_status: Literal["not_selected"]
    lifecycle_status: Literal["registered_demo"]
    operational_detection_approved: Literal[False]

    @classmethod
    def from_descriptor(
        cls, descriptor: ActiveModelDescriptor
    ) -> "InferenceModelSummary":
        return cls.model_validate(
            descriptor.model_dump(
                include={
                    "model_id",
                    "algorithm",
                    "experiment_id",
                    "feature_schema_version",
                    "dataset_id",
                    "dataset_integrity_digest",
                    "dataset_provenance_type",
                    "evaluation_status",
                    "model_selection_status",
                    "lifecycle_status",
                    "operational_detection_approved",
                }
            )
        )


class InferenceLimitation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    code: Literal[
        "synthetic_model_only",
        "not_security_verdict",
        "probability_not_calibrated",
        "static_analysis_only",
        "bounded_analysis",
    ]
    description: Annotated[str, Field(min_length=1, max_length=512)]


class MLInferenceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    inference_id: UUID
    analysis_id: UUID
    inference_mode: InferenceMode
    demo_only: Literal[True] = True
    status: Literal["completed"] = "completed"
    prediction: InferencePrediction
    model: InferenceModelSummary
    limitations: tuple[InferenceLimitation, ...]

    @model_validator(mode="after")
    def require_limitations(self) -> Self:
        required = {
            "synthetic_model_only",
            "not_security_verdict",
            "probability_not_calibrated",
            "static_analysis_only",
            "bounded_analysis",
        }
        if {item.code for item in self.limitations} != required:
            raise ValueError(
                "inference response requires every demonstration limitation"
            )
        if len(self.limitations) != len(required):
            raise ValueError("inference limitations must be unique")
        return self
