from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.content_inspection import (
    EntropySummary,
    StaticIndicator,
    StringExtractionSummary,
)
from app.schemas.fingerprint import DetectedFormat, FormatConsistency


class StaticAnalysisFingerprint(BaseModel):
    """Identity and format evidence derived from the accepted byte stream."""

    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    size_bytes: Annotated[int, Field(gt=0)]
    detected_format: DetectedFormat
    format_consistency: FormatConsistency


class StaticAnalysisContent(BaseModel):
    entropy: EntropySummary
    strings: StringExtractionSummary


class AnalysisLimitation(BaseModel):
    model_config = ConfigDict(frozen=True)

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
        return value
