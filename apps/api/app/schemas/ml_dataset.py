from datetime import date
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.ml_features import (
    FEATURE_SCHEMA_VERSION,
    FeatureSchemaVersion,
    MLFeatureVector,
)

DatasetLabelName = Literal["benign", "malicious", "unknown"]
DatasetSplit = Literal["training", "validation", "test", "unassigned"]
ProvenanceKind = Literal["synthetic", "owned", "licensed", "research", "unknown"]


class SampleIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    record_id: Annotated[str, Field(min_length=1, max_length=128)]


class DatasetLabel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    value: DatasetLabelName
    source: Annotated[str, Field(min_length=1, max_length=256)]
    confidence: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)] | None = None
    verified_on: date | None = None
    synthetic: bool = False


class FeatureExtractionSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    extractor_version: Literal["static-analysis-adapter/1.0.0"] = (
        "static-analysis-adapter/1.0.0"
    )
    feature_schema_version: FeatureSchemaVersion = FEATURE_SCHEMA_VERSION
    minimum_string_length: Annotated[int, Field(gt=0, le=256)]
    maximum_retained_strings: Annotated[int, Field(gt=0, le=1000)]
    maximum_characters_per_string: Annotated[int, Field(gt=0, le=4096)]
    maximum_indicators: Annotated[int, Field(gt=0, le=1000)]

    @model_validator(mode="after")
    def validate_string_bounds(self) -> Self:
        if self.maximum_characters_per_string < self.minimum_string_length:
            raise ValueError(
                "maximum_characters_per_string must be at least minimum_string_length"
            )
        return self


class DatasetProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    dataset_id: Annotated[str, Field(min_length=1, max_length=128)]
    source_kind: ProvenanceKind
    source_description: Annotated[str, Field(min_length=1, max_length=512)]
    collected_on: date
    license: Annotated[str, Field(min_length=1, max_length=256)]
    usage_restrictions: Annotated[str, Field(min_length=1, max_length=512)]


class MLDatasetRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    identity: SampleIdentity
    features: MLFeatureVector
    label: DatasetLabel
    provenance: DatasetProvenance
    extraction: FeatureExtractionSettings
    split: DatasetSplit = "unassigned"

    @model_validator(mode="after")
    def validate_contract_versions(self) -> Self:
        if (
            self.features.feature_schema_version
            != self.extraction.feature_schema_version
        ):
            raise ValueError("feature and extraction schema versions must match")
        return self
