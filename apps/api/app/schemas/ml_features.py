from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictFloat, StrictInt

from app.schemas.fingerprint import DetectedFormat, FormatConsistency

FeatureSchemaVersion = Literal["1.0.0"]
FEATURE_SCHEMA_VERSION: FeatureSchemaVersion = "1.0.0"

PredictiveFeatureName = Literal[
    "file_size_bytes",
    "shannon_entropy",
    "printable_string_count",
    "retained_string_count",
    "indicator_count",
    "detected_format",
    "format_consistency",
    "has_url_candidate",
    "has_ipv4_candidate",
    "has_powershell_reference",
    "has_encoded_command_token",
    "has_script_reference",
    "strings_truncated",
    "indicators_truncated",
]

PREDICTIVE_FEATURE_ORDER: tuple[PredictiveFeatureName, ...] = (
    "file_size_bytes",
    "shannon_entropy",
    "printable_string_count",
    "retained_string_count",
    "indicator_count",
    "detected_format",
    "format_consistency",
    "has_url_candidate",
    "has_ipv4_candidate",
    "has_powershell_reference",
    "has_encoded_command_token",
    "has_script_reference",
    "strings_truncated",
    "indicators_truncated",
)


class MLFeatureVector(BaseModel):
    """Versioned observations only; identity, labels, and provenance are excluded."""

    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    file_size_bytes: Annotated[StrictInt, Field(gt=0)]
    shannon_entropy: Annotated[StrictFloat, Field(ge=0, le=8)]
    printable_string_count: Annotated[StrictInt, Field(ge=0)]
    retained_string_count: Annotated[StrictInt, Field(ge=0)]
    indicator_count: Annotated[StrictInt, Field(ge=0)]
    detected_format: DetectedFormat
    format_consistency: FormatConsistency
    has_url_candidate: StrictBool
    has_ipv4_candidate: StrictBool
    has_powershell_reference: StrictBool
    has_encoded_command_token: StrictBool
    has_script_reference: StrictBool
    strings_truncated: StrictBool
    indicators_truncated: StrictBool
    feature_schema_version: FeatureSchemaVersion = FEATURE_SCHEMA_VERSION

    def ordered_predictive_values(self) -> tuple[int | float | str | bool, ...]:
        """Return the stable model-input order; schema version is metadata."""
        return tuple(getattr(self, name) for name in PREDICTIVE_FEATURE_ORDER)
