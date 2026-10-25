from typing import Annotated, Literal

from pydantic import BaseModel, Field

from app.schemas.fingerprint import DetectedFormat

IndicatorCategory = Literal["network", "command", "file"]


class EntropySummary(BaseModel):
    shannon_entropy: Annotated[float, Field(ge=0, le=8)]
    total_bytes: Annotated[int, Field(gt=0)]


class StringExtractionSummary(BaseModel):
    observed_count: Annotated[int, Field(ge=0)]
    retained_count: Annotated[int, Field(ge=0)]
    truncated: bool
    raw_strings_exposed: Literal[False]
    minimum_length: Annotated[int, Field(gt=0)]
    maximum_retained_strings: Annotated[int, Field(gt=0)]
    maximum_characters_per_string: Annotated[int, Field(gt=0)]


class StaticIndicator(BaseModel):
    id: str
    category: IndicatorCategory
    description: str
    source: Literal["printable_ascii"]
    offset: Annotated[int | None, Field(ge=0)] = None
    evidence: Annotated[str | None, Field(max_length=96)] = None
    severity: Literal["informational"] = "informational"


class ContentInspectionResponse(BaseModel):
    filename: Annotated[str, Field(min_length=1, max_length=255)]
    size_bytes: Annotated[int, Field(gt=0)]
    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    detected_format: DetectedFormat
    entropy: EntropySummary
    strings: StringExtractionSummary
    indicators: list[StaticIndicator]
    indicators_truncated: bool
