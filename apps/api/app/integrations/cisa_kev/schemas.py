from __future__ import annotations

from datetime import date, datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field


class CISAKEVEntry(BaseModel):
    model_config = ConfigDict(extra="ignore")

    cveID: Annotated[str, Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,19}$", max_length=32)]
    vendorProject: Annotated[str, Field(min_length=1, max_length=512)]
    product: Annotated[str, Field(min_length=1, max_length=512)]
    vulnerabilityName: Annotated[str, Field(min_length=1, max_length=1024)]
    dateAdded: date
    shortDescription: Annotated[str, Field(min_length=1, max_length=8192)]
    requiredAction: Annotated[str, Field(min_length=1, max_length=8192)]
    dueDate: date
    knownRansomwareCampaignUse: Annotated[
        str | None, Field(default=None, min_length=1, max_length=128)
    ]
    forensicTriage: Annotated[
        str | None, Field(default=None, min_length=1, max_length=128)
    ]
    notes: Annotated[str | None, Field(default=None, max_length=8192)]
    cwes: (
        tuple[Annotated[str, Field(pattern=r"^CWE-[0-9]+$", max_length=64)], ...] | None
    ) = None


class CISAKEVCatalog(BaseModel):
    model_config = ConfigDict(extra="ignore")

    title: Annotated[str | None, Field(default=None, min_length=1, max_length=512)]
    catalogVersion: Annotated[str, Field(min_length=1, max_length=128)]
    dateReleased: datetime
    count: Annotated[int, Field(ge=0)]
    vulnerabilities: tuple[CISAKEVEntry, ...]
