from __future__ import annotations

from datetime import date
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _probability(value: Any) -> Decimal:
    if isinstance(value, bool):
        raise ValueError("probability must be decimal data")
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError) as error:
        raise ValueError("probability must be decimal data") from error
    if not parsed.is_finite() or parsed < 0 or parsed > 1:
        raise ValueError("probability must be finite and between zero and one")
    return parsed


class FIRSTEPSSDatum(BaseModel):
    model_config = ConfigDict(extra="ignore")

    cve: Annotated[str, Field(pattern=r"^CVE-(1999|2\d{3})-\d{4,}$", max_length=32)]
    epss: Decimal
    percentile: Decimal
    date: date

    _validate_epss = field_validator("epss", mode="before")(_probability)
    _validate_percentile = field_validator("percentile", mode="before")(_probability)


class FIRSTEPSSResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    status: Annotated[str, Field(min_length=1, max_length=64)]
    status_code: Annotated[int, Field(alias="status-code")]
    version: Annotated[str, Field(min_length=1, max_length=32)]
    access: Annotated[str, Field(min_length=1, max_length=128)]
    total: Annotated[int, Field(ge=0)]
    offset: Annotated[int, Field(ge=0)]
    limit: Annotated[int, Field(ge=0)]
    data: tuple[FIRSTEPSSDatum, ...]

    @field_validator("status")
    @classmethod
    def require_ok(cls, value: str) -> str:
        if value != "OK":
            raise ValueError("EPSS provider status must be OK")
        return value

    @field_validator("status_code")
    @classmethod
    def require_success_code(cls, value: int) -> int:
        if value != 200:
            raise ValueError("EPSS provider status code must be 200")
        return value

    def model_post_init(self, __context: Any) -> None:
        if self.total != len(self.data):
            raise ValueError("EPSS total does not match returned data")
        if self.offset != 0:
            raise ValueError("EPSS point query offset must be zero")
        if self.total > self.limit:
            raise ValueError("EPSS response indicates hidden paginated results")

    def ensure_point_query(self) -> Self:
        if self.total > 1:
            raise ValueError("EPSS point query returned multiple records")
        return self
