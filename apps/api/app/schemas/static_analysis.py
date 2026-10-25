from datetime import datetime, timedelta
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas.content_inspection import (
    EntropySummary,
    StaticIndicator,
    StringExtractionSummary,
)
from app.schemas.fingerprint import DetectedFormat, FormatConsistency


class StaticAnalysisFingerprint(BaseModel):
    """Identity and format evidence derived from the accepted byte stream."""

    model_config = ConfigDict(extra="forbid")

    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    size_bytes: Annotated[int, Field(gt=0)]
    detected_format: DetectedFormat
    format_consistency: FormatConsistency


class StaticAnalysisContent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entropy: EntropySummary
    strings: StringExtractionSummary


class AnalysisLimitation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    code: Literal[
        "static_only",
        "no_execution",
        "no_malware_verdict",
        "format_not_validity",
        "entropy_not_maliciousness",
        "text_indicators_may_be_benign",
        "configured_bounds_apply",
    ]
    description: str


class StaticAnalysisResponse(BaseModel):
    """Non-persistent, descriptive report for one synchronous operation."""

    model_config = ConfigDict(extra="forbid")

    analysis_id: UUID
    analysis_type: Literal["static"]
    status: Literal["completed"]
    filename: Annotated[str, Field(min_length=1, max_length=255)]
    created_at: datetime
    completed_at: datetime
    fingerprint: StaticAnalysisFingerprint
    content: StaticAnalysisContent
    indicators: list[StaticIndicator]
    indicators_truncated: bool
    analysis_limitations: list[AnalysisLimitation]

    @field_validator("created_at", "completed_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        if value.utcoffset() != timedelta(0):
            raise ValueError("timestamp must use UTC")
        return value

    @model_validator(mode="after")
    def validate_report_consistency(self) -> Self:
        if self.completed_at < self.created_at:
            raise ValueError("completed_at must not be earlier than created_at")
        if self.fingerprint.size_bytes != self.content.entropy.total_bytes:
            raise ValueError(
                "fingerprint and entropy byte counts must describe the same input"
            )
        return self
