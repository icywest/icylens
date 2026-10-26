from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import Field, field_validator

from app.schemas.vulnerability import StrictContract, normalize_utc

ATTACK_TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
ATTACK_TACTIC_ID = re.compile(r"^TA\d{4}$")


class ATTACKObjectStatus(str, Enum):
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    REVOKED = "revoked"
    UNKNOWN = "unknown"


class ATTACKExternalReference(StrictContract):
    source_name: Annotated[str, Field(min_length=1, max_length=256)]
    external_id: Annotated[str | None, Field(default=None, max_length=128)]
    url: Annotated[str | None, Field(default=None, max_length=4096)]
    description: Annotated[str | None, Field(default=None, max_length=8192)]


class ATTACKProvenance(StrictContract):
    domain: Literal["enterprise-attack"]
    attack_version: Annotated[str, Field(pattern=r"^\d+\.\d+$", max_length=16)]
    source_url: Annotated[str, Field(pattern=r"^https://", max_length=4096)]
    source_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    imported_at: datetime

    _normalize_imported_at = field_validator("imported_at")(normalize_utc)


class ATTACKTactic(StrictContract):
    attack_id: Annotated[str, Field(pattern=r"^TA\d{4}$")]
    stix_id: Annotated[str, Field(pattern=r"^x-mitre-tactic--[0-9a-f-]{36}$")]
    name: Annotated[str, Field(min_length=1, max_length=512)]
    description: Annotated[str | None, Field(default=None, max_length=131_072)]
    short_name: Annotated[str | None, Field(default=None, max_length=128)]
    domain: Literal["enterprise-attack"]
    references: tuple[ATTACKExternalReference, ...]
    attack_spec_version: Annotated[str | None, Field(default=None, max_length=32)]
    object_version: Annotated[str | None, Field(default=None, max_length=32)]
    status: ATTACKObjectStatus
    revoked: bool | None
    deprecated: bool | None
    created: datetime | None
    modified: datetime | None


class ATTACKTechnique(StrictContract):
    attack_id: Annotated[str, Field(pattern=r"^T\d{4}(?:\.\d{3})?$")]
    stix_id: Annotated[str, Field(pattern=r"^attack-pattern--[0-9a-f-]{36}$")]
    name: Annotated[str, Field(min_length=1, max_length=512)]
    description: Annotated[str | None, Field(default=None, max_length=131_072)]
    domain: Literal["enterprise-attack"]
    parent_attack_id: Annotated[str | None, Field(default=None, pattern=r"^T\d{4}$")]
    is_subtechnique: bool
    tactic_ids: tuple[Annotated[str, Field(pattern=r"^TA\d{4}$")], ...]
    platforms: tuple[Annotated[str, Field(min_length=1, max_length=128)], ...]
    references: tuple[ATTACKExternalReference, ...]
    attack_spec_version: Annotated[str | None, Field(default=None, max_length=32)]
    object_version: Annotated[str | None, Field(default=None, max_length=32)]
    status: ATTACKObjectStatus
    revoked: bool | None
    deprecated: bool | None
    created: datetime | None
    modified: datetime | None


class ATTACKRelationship(StrictContract):
    stix_id: Annotated[str, Field(pattern=r"^relationship--[0-9a-f-]{36}$")]
    source_stix_id: Annotated[str, Field(min_length=3, max_length=128)]
    target_stix_id: Annotated[str, Field(min_length=3, max_length=128)]
    relationship_type: Annotated[str, Field(min_length=1, max_length=128)]
    domain: Literal["enterprise-attack"]
    attack_version: Annotated[str, Field(pattern=r"^\d+\.\d+$")]
    revoked: bool | None
    deprecated: bool | None


class ATTACKCatalogStatistics(StrictContract):
    object_count: int
    tactic_count: int
    technique_count: int
    subtechnique_count: int
    relationship_count: int
    active_technique_count: int
    retired_technique_count: int


class ATTACKCatalogStatus(StrictContract):
    available: bool
    validation_status: Literal["validated", "unavailable"]
    provenance: ATTACKProvenance | None
    statistics: ATTACKCatalogStatistics | None
    retired_policy: Literal["retained_excluded_by_default"]
    scientific_boundary: Literal["knowledge_not_observation"] = (
        "knowledge_not_observation"
    )


class ATTACKTacticList(StrictContract):
    items: tuple[ATTACKTactic, ...]
    total: int
    offset: int
    limit: int
    provenance: ATTACKProvenance


class ATTACKTechniqueList(StrictContract):
    items: tuple[ATTACKTechnique, ...]
    total: int
    offset: int
    limit: int
    provenance: ATTACKProvenance
