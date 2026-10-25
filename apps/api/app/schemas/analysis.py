from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.common import (
    AnalysisEngine,
    AnalysisStatus,
    ThreatVerdict,
    validate_filename,
)


class AnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    filename: Annotated[
        str,
        Field(
            min_length=1,
            max_length=255,
            description=(
                "File name only. Path separators, control characters, and the "
                "special components '.' and '..' are rejected."
            ),
        ),
    ]

    mode: Literal["static", "educational"] = Field(
        default="static",
        description="Validation mode; no analysis is executed.",
    )

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, value: str) -> str:
        return validate_filename(value)


class AnalysisIndicator(BaseModel):
    name: str
    description: str
    source: AnalysisEngine
    severity: Literal["info", "low", "medium", "high", "critical"]


class EngineResult(BaseModel):
    engine: AnalysisEngine
    status: Literal["completed", "skipped", "failed"]
    indicators: list[AnalysisIndicator] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    verdict: ThreatVerdict
    risk_score: Annotated[float | None, Field(ge=0, le=100)] = None

    engines: list[EngineResult] = Field(default_factory=list)


class AnalysisResponse(BaseModel):
    analysis_id: UUID
    filename: str
    status: AnalysisStatus
    created_at: datetime
    completed_at: datetime | None = None
    result: AnalysisResult | None = None
