from __future__ import annotations

from datetime import date, datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Annotated, Literal

from pydantic import Field, field_serializer, field_validator, model_validator

from app.schemas.vulnerability import StrictContract, normalize_cve_id


class EPSSLookupStatus(str, Enum):
    AVAILABLE = "available"
    NOT_SCORED = "not_scored"
    TEMPORARILY_UNAVAILABLE = "temporarily_unavailable"


class EPSSFreshness(str, Enum):
    CURRENT = "current"
    STALE = "stale"
    HISTORICAL = "historical"
    UNAVAILABLE = "unavailable"


class EPSSProvenance(StrictContract):
    provider: Literal["FIRST"] = "FIRST"
    api_version: Annotated[str, Field(min_length=1, max_length=32)]
    source_url: Literal["https://api.first.org/data/v1/epss"]
    retrieved_at: datetime
    source_score_date: date | None
    model_version: Annotated[str | None, Field(default=None, max_length=64)] = None

    @field_validator("retrieved_at")
    @classmethod
    def normalize_retrieved_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("retrieved_at must include a timezone")
        return value.astimezone(timezone.utc)


class EPSSLookupResult(StrictContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    cve_id: Annotated[str, Field(max_length=32)]
    status: EPSSLookupStatus
    score: Annotated[Decimal | None, Field(default=None, ge=0, le=1)]
    percentile: Annotated[Decimal | None, Field(default=None, ge=0, le=1)]
    score_date: date | None
    freshness: EPSSFreshness
    provenance: EPSSProvenance
    limitations: tuple[Annotated[str, Field(min_length=1, max_length=512)], ...]

    _validate_cve = field_validator("cve_id")(normalize_cve_id)

    @field_serializer("score", "percentile", when_used="json")
    def serialize_decimal(self, value: Decimal | None) -> str | None:
        return None if value is None else format(value, "f")

    @model_validator(mode="after")
    def require_status_consistency(self) -> EPSSLookupResult:
        values = (self.score, self.percentile, self.score_date)
        if self.status is EPSSLookupStatus.AVAILABLE and any(
            value is None for value in values
        ):
            raise ValueError("available EPSS result requires score data")
        if self.status is not EPSSLookupStatus.AVAILABLE and any(
            value is not None for value in values
        ):
            raise ValueError("unavailable EPSS result cannot contain score data")
        if (
            self.status is EPSSLookupStatus.AVAILABLE
            and self.freshness is EPSSFreshness.UNAVAILABLE
        ):
            raise ValueError("available EPSS result requires dated freshness")
        if (
            self.status is not EPSSLookupStatus.AVAILABLE
            and self.freshness is not EPSSFreshness.UNAVAILABLE
        ):
            raise ValueError("unavailable EPSS result requires unavailable freshness")
        if self.provenance.source_score_date != self.score_date:
            raise ValueError("EPSS provenance score date must match the record")
        return self
