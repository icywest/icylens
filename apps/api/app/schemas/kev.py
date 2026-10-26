from __future__ import annotations

import re
from datetime import date, datetime, timezone
from enum import Enum
from typing import Annotated, Literal

from pydantic import Field, field_validator

from app.schemas.vulnerability import StrictContract


def validate_kev_cve_id(value: str) -> str:
    if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,19}", value):
        raise ValueError("CVE ID must match CVE-YYYY-NNNN")
    return value


def utc_timestamp(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return value.astimezone(timezone.utc)


class KEVFreshnessStatus(str, Enum):
    FRESH = "fresh"
    STALE = "stale"
    UNAVAILABLE = "unavailable"
    NEVER_LOADED = "never_loaded"


class KEVPresenceStatus(str, Enum):
    LISTED = "listed"
    NOT_LISTED = "not_listed"
    NOT_ESTABLISHED = "not_established"


class KEVProvenance(StrictContract):
    provider: Literal["CISA"] = "CISA"
    source_url: Literal[
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    ]
    catalog_version: Annotated[str, Field(min_length=1, max_length=128)]
    catalog_date_released: datetime

    _normalize_release = field_validator("catalog_date_released")(utc_timestamp)


class KEVRecord(StrictContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    cve_id: Annotated[str, Field(max_length=32)]
    vendor_project: Annotated[str, Field(min_length=1, max_length=512)]
    product: Annotated[str, Field(min_length=1, max_length=512)]
    vulnerability_name: Annotated[str, Field(min_length=1, max_length=1024)]
    date_added: date
    short_description: Annotated[str, Field(min_length=1, max_length=8192)]
    required_action: Annotated[str, Field(min_length=1, max_length=8192)]
    due_date: date
    known_ransomware_campaign_use: Annotated[
        str | None, Field(default=None, max_length=128)
    ]
    forensic_triage: Annotated[str | None, Field(default=None, max_length=128)]
    notes: Annotated[str | None, Field(default=None, max_length=8192)]
    cwes: tuple[Annotated[str, Field(max_length=64)], ...] | None
    source: Literal["CISA KEV"] = "CISA KEV"
    provenance: KEVProvenance

    _validate_cve = field_validator("cve_id")(validate_kev_cve_id)


class KEVCatalogStatus(StrictContract):
    availability: KEVFreshnessStatus
    catalog_version: str | None
    date_released: datetime | None
    fetched_at: datetime | None
    freshness_age_seconds: float | None
    count: int | None


class KEVLookupResult(StrictContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    cve_id: Annotated[str, Field(max_length=32)]
    presence: KEVPresenceStatus
    record: KEVRecord | None
    catalog: KEVCatalogStatus
    limitations: tuple[Annotated[str, Field(min_length=1, max_length=512)], ...]

    _validate_cve = field_validator("cve_id")(validate_kev_cve_id)
