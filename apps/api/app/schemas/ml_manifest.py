from datetime import datetime, timedelta
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas.ml_features import (
    FEATURE_SCHEMA_VERSION,
    FeatureSchemaVersion,
)

ManifestSchemaVersion = Literal["1.0.0"]
BuilderVersion = Literal["dataset-builder/1.0.0"]
SplitAlgorithmVersion = Literal["sha256-stratified-v1"]
MANIFEST_SCHEMA_VERSION: ManifestSchemaVersion = "1.0.0"
BUILDER_VERSION: BuilderVersion = "dataset-builder/1.0.0"
SPLIT_ALGORITHM_VERSION: SplitAlgorithmVersion = "sha256-stratified-v1"


class SplitConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    algorithm_version: SplitAlgorithmVersion = SPLIT_ALGORITHM_VERSION
    random_seed: Annotated[int, Field(ge=0, le=2**63 - 1)] = 42
    training_fraction: Annotated[float, Field(gt=0, lt=1)] = 0.7
    validation_fraction: Annotated[float, Field(gt=0, lt=1)] = 0.15
    test_fraction: Annotated[float, Field(gt=0, lt=1)] = 0.15
    stratification: Literal["label"] = "label"
    grouping_policy: Literal["sha256_exact_only"] = "sha256_exact_only"
    minimum_per_class_per_split: Annotated[int, Field(ge=1)] = 1
    feature_schema_version: FeatureSchemaVersion = FEATURE_SCHEMA_VERSION
    respect_existing_assignments: Literal[True] = True

    @model_validator(mode="after")
    def validate_fractions(self) -> Self:
        total = self.training_fraction + self.validation_fraction + self.test_fraction
        if abs(total - 1.0) > 1e-12:
            raise ValueError("split fractions must sum to 1.0")
        return self


class ManifestValidationSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    input_count: Annotated[int, Field(ge=0)]
    structurally_valid_count: Annotated[int, Field(ge=0)]
    governance_eligible_count: Annotated[int, Field(ge=0)]
    training_eligible_count: Annotated[int, Field(ge=0)]
    accepted_count: Annotated[int, Field(ge=0)]
    excluded_count: Annotated[int, Field(ge=0)]
    warning_count: Annotated[int, Field(ge=0)]
    error_count: Annotated[int, Field(ge=0)]
    issue_code_counts: dict[str, Annotated[int, Field(ge=1)]]
    ready_for_training: bool


class DatasetManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest_schema_version: ManifestSchemaVersion = MANIFEST_SCHEMA_VERSION
    dataset_id: Annotated[
        str,
        Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$"),
    ]
    dataset_version: Annotated[
        str,
        Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"),
    ]
    feature_schema_version: FeatureSchemaVersion = FEATURE_SCHEMA_VERSION
    builder_version: BuilderVersion = BUILDER_VERSION
    extraction_versions: tuple[str, ...]
    record_count: Annotated[int, Field(ge=0)]
    eligible_record_count: Annotated[int, Field(ge=0)]
    excluded_record_count: Annotated[int, Field(ge=0)]
    label_counts: dict[str, Annotated[int, Field(ge=0)]]
    split_counts: dict[str, Annotated[int, Field(ge=0)]]
    source_identifiers: tuple[str, ...]
    validation_summary: ManifestValidationSummary
    split_configuration: SplitConfiguration
    integrity_algorithm: Literal["sha256-canonical-json-v1"] = (
        "sha256-canonical-json-v1"
    )
    content_integrity_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    created_at: datetime
    created_by: Literal["icylens-local-dataset-builder"] = (
        "icylens-local-dataset-builder"
    )

    @field_validator("created_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        if value.utcoffset() != timedelta(0):
            raise ValueError("created_at must use UTC")
        return value

    @model_validator(mode="after")
    def validate_counts(self) -> Self:
        if self.record_count != self.eligible_record_count:
            raise ValueError("released records and eligible records must match")
        if self.record_count != sum(self.label_counts.values()):
            raise ValueError("label counts must equal record count")
        if self.record_count != sum(self.split_counts.values()):
            raise ValueError("split counts must equal record count")
        if self.record_count != self.validation_summary.accepted_count:
            raise ValueError("validation accepted count must equal record count")
        if self.excluded_record_count != self.validation_summary.excluded_count:
            raise ValueError("validation excluded count must match manifest")
        return self
