from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Annotated, Literal, Self, TypeAlias
from uuid import UUID

from pydantic import Field, model_validator

from app.schemas.evidence import (
    EvidenceBatch,
    EvidenceId,
    EvidenceOriginType,
    EvidenceSourceModule,
    EvidenceTimestamp,
    EvidenceTrustClassification,
    EvidenceVerificationStatus,
)
from app.schemas.vulnerability import StrictContract

IDENTITY_SCHEMA_VERSION = "1.0.0"
MAX_IDENTITY_CLAIMS = 512
MAX_IDENTITY_MATCHES = 512
MAX_IDENTITY_GROUPS = 256
MAX_IDENTITY_CONFLICTS = 256
MAX_IDENTITY_REFERENCES = 256
MAX_IDENTITY_OUTPUT_BYTES = 1024 * 1024
MAX_GROUP_MEMBERS = 256
MAX_MATCH_EVIDENCE_IDS = 256
MAX_EXPLANATION_REFERENCES = 16

IdentityClaimId: TypeAlias = Annotated[
    str, Field(pattern=r"^idc_[0-9a-f]{64}$", max_length=68)
]
IdentityMatchId: TypeAlias = Annotated[
    str, Field(pattern=r"^idm_[0-9a-f]{64}$", max_length=68)
]
IdentityConflictId: TypeAlias = Annotated[
    str, Field(pattern=r"^idf_[0-9a-f]{64}$", max_length=68)
]
ResolvedIdentityGroupId: TypeAlias = Annotated[
    str, Field(pattern=r"^idg_[0-9a-f]{64}$", max_length=68)
]


def _content_id(prefix: str, value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return f"{prefix}_{hashlib.sha256(encoded).hexdigest()}"


class IdentityType(str, Enum):
    FILE_CONTENT = "file_content"
    PROCESS_INSTANCE = "process_instance"
    VULNERABILITY = "vulnerability"
    ML_MODEL = "ml_model"
    ATTACK_TECHNIQUE = "attack_technique"
    ANALYSIS = "analysis"


class IdentityNamespace(str, Enum):
    SHA256 = "sha256"
    PROCESS_INSTANCE_HOST = "process_instance_host"
    CVE = "cve"
    MODEL_ID_VERSION = "model_id_version"
    ATTACK_STIX_CATALOG = "attack_stix_catalog"
    ANALYSIS_UUID = "analysis_uuid"


class IdentityResolutionStatus(str, Enum):
    SAME_IDENTITY = "same_identity"
    COMPATIBLE_CONTEXT = "compatible_context"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    CONFLICTING_IDENTITY = "conflicting_identity"
    NOT_COMPARABLE = "not_comparable"


class IdentityClaimAvailability(str, Enum):
    AVAILABLE = "available"
    UNRESOLVED = "unresolved"


class IdentityConflictCode(str, Enum):
    CONFLICTING_ANALYSIS_SUBJECT = "conflicting_analysis_subject"
    INCOMPATIBLE_NAMESPACE = "incompatible_namespace"
    UNSUPPORTED_NAMESPACE = "unsupported_namespace"
    MISSING_REQUIRED_ATTRIBUTE = "missing_required_attribute"
    DUPLICATE_EVIDENCE_REFERENCE = "duplicate_evidence_reference"
    CONTRADICTORY_PROVENANCE = "contradictory_provenance"
    IDENTITY_REFERENCE_MISMATCH = "identity_reference_mismatch"


class IdentityReference(StrictContract):
    identity_type: IdentityType
    namespace: IdentityNamespace
    reference_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    scope_category: Annotated[str, Field(min_length=1, max_length=128)]
    canonical_value_disclosed: Literal[False] = False


class IdentityClaim(StrictContract):
    claim_id: IdentityClaimId
    evidence_id: EvidenceId
    identity_type: IdentityType
    availability: IdentityClaimAvailability
    reference: IdentityReference | None
    required_attributes: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=64)], ...],
        Field(min_length=1, max_length=8),
    ]
    missing_attributes: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=64)], ...],
        Field(max_length=8),
    ]
    source_module: EvidenceSourceModule
    verification_status: EvidenceVerificationStatus
    limitations: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...],
        Field(max_length=8),
    ]

    @model_validator(mode="after")
    def enforce_availability(self) -> Self:
        if self.availability is IdentityClaimAvailability.AVAILABLE:
            if self.reference is None or self.missing_attributes:
                raise ValueError("available identity claim must be complete")
        elif self.reference is not None or not self.missing_attributes:
            raise ValueError(
                "unresolved identity claim must declare missing attributes"
            )
        material = {
            "evidence_id": self.evidence_id,
            "identity_type": self.identity_type.value,
            "namespace": (
                None if self.reference is None else self.reference.namespace.value
            ),
            "reference_digest": (
                None if self.reference is None else self.reference.reference_digest
            ),
            "required": self.required_attributes,
            "missing": self.missing_attributes,
        }
        if self.claim_id != _content_id("idc", material):
            raise ValueError("claim ID does not match canonical claim content")
        return self


class IdentityContext(StrictContract):
    evidence_id: EvidenceId
    source_module: EvidenceSourceModule
    source_phase: Literal["02", "03", "04", "05"]
    source_analysis_id: UUID
    subject_type: Annotated[str, Field(min_length=1, max_length=64)]
    temporal_context: Annotated[tuple[EvidenceTimestamp, ...], Field(max_length=8)]
    environment_scope: Annotated[str, Field(min_length=1, max_length=128)]
    origin_type: EvidenceOriginType
    trust_classification: EvidenceTrustClassification
    synthetic: bool
    verification_status: EvidenceVerificationStatus
    common_batch_assumed: Literal[False] = False


class IdentityMatchEvidence(StrictContract):
    match_id: IdentityMatchId
    rule_id: Annotated[str, Field(pattern=r"^IR-[A-Z]+-[0-9]{3}$", max_length=24)]
    rule_version: Literal["1.0.0"] = "1.0.0"
    status: IdentityResolutionStatus
    identity_type: IdentityType | None
    namespace: IdentityNamespace | None
    evidence_ids: Annotated[
        tuple[EvidenceId, ...], Field(min_length=1, max_length=MAX_MATCH_EVIDENCE_IDS)
    ]
    matching_attributes: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=64)], ...],
        Field(max_length=8),
    ]
    explanation: Annotated[str, Field(min_length=1, max_length=512)]
    explanation_references: Annotated[
        tuple[EvidenceId, ...], Field(max_length=MAX_EXPLANATION_REFERENCES)
    ]
    limitations: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...],
        Field(min_length=1, max_length=8),
    ]
    identity_confirmed: bool
    execution_confirmed: Literal[False] = False
    threat_correlation_performed: Literal[False] = False

    @model_validator(mode="after")
    def enforce_status_semantics(self) -> Self:
        if self.status is IdentityResolutionStatus.SAME_IDENTITY:
            if len(self.evidence_ids) < 2 or not self.identity_confirmed:
                raise ValueError("same identity requires multiple confirmed references")
            if self.identity_type is None or self.namespace is None:
                raise ValueError("same identity requires a typed namespace")
        elif self.identity_confirmed:
            raise ValueError("only same_identity can confirm identity")
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("match evidence IDs must be unique")
        material = {
            "rule_id": self.rule_id,
            "status": self.status.value,
            "identity_type": (
                None if self.identity_type is None else self.identity_type.value
            ),
            "namespace": None if self.namespace is None else self.namespace.value,
            "evidence_ids": self.evidence_ids,
            "attributes": self.matching_attributes,
        }
        if self.match_id != _content_id("idm", material):
            raise ValueError("match ID does not match canonical match content")
        return self


class IdentityConflict(StrictContract):
    conflict_id: IdentityConflictId
    code: IdentityConflictCode
    identity_type: IdentityType | None
    namespace: IdentityNamespace | None
    evidence_ids: Annotated[
        tuple[EvidenceId, ...], Field(min_length=1, max_length=MAX_MATCH_EVIDENCE_IDS)
    ]
    field_categories: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=64)], ...],
        Field(min_length=1, max_length=8),
    ]
    explanation: Annotated[str, Field(min_length=1, max_length=512)]
    source_precedence_applied: Literal[False] = False

    @model_validator(mode="after")
    def verify_identifier(self) -> Self:
        material = {
            "code": self.code.value,
            "evidence_ids": self.evidence_ids,
            "identity_type": (
                None if self.identity_type is None else self.identity_type.value
            ),
            "namespace": None if self.namespace is None else self.namespace.value,
            "fields": self.field_categories,
        }
        if self.conflict_id != _content_id("idf", material):
            raise ValueError("conflict ID does not match canonical conflict content")
        return self


class ResolvedIdentityGroup(StrictContract):
    group_id: ResolvedIdentityGroupId
    identity_type: IdentityType
    namespace: IdentityNamespace
    member_evidence_ids: Annotated[
        tuple[EvidenceId, ...], Field(min_length=2, max_length=MAX_GROUP_MEMBERS)
    ]
    supporting_match_ids: Annotated[
        tuple[IdentityMatchId, ...],
        Field(min_length=1, max_length=MAX_IDENTITY_MATCHES),
    ]
    limitations: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...],
        Field(min_length=1, max_length=8),
    ]
    compatible_context_used_for_grouping: Literal[False] = False

    @model_validator(mode="after")
    def verify_identifier(self) -> Self:
        material = {
            "identity_type": self.identity_type.value,
            "namespace": self.namespace.value,
            "members": self.member_evidence_ids,
            "matches": self.supporting_match_ids,
        }
        if self.group_id != _content_id("idg", material):
            raise ValueError("group ID does not match canonical group content")
        return self


class IdentityResolutionRule(StrictContract):
    rule_id: Annotated[str, Field(pattern=r"^IR-[A-Z]+-[0-9]{3}$", max_length=24)]
    version: Literal["1.0.0"] = "1.0.0"
    identity_type: IdentityType | None
    applicable_subject_types: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=64)], ...],
        Field(min_length=1, max_length=8),
    ]
    required_attributes: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=64)], ...],
        Field(min_length=1, max_length=8),
    ]
    allowed_namespaces: Annotated[tuple[IdentityNamespace, ...], Field(max_length=4)]
    context_constraints: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=256)], ...],
        Field(max_length=8),
    ]
    conflict_conditions: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=256)], ...],
        Field(max_length=8),
    ]
    explanation_template: Annotated[str, Field(min_length=1, max_length=512)]
    limitations: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...],
        Field(min_length=1, max_length=8),
    ]
    dynamic_expression: Literal[False] = False


class IdentityResolutionSummary(StrictContract):
    evidence_records: Annotated[int, Field(ge=1, le=256)]
    claims: Annotated[int, Field(ge=0, le=MAX_IDENTITY_CLAIMS)]
    resolved_claims: Annotated[int, Field(ge=0, le=MAX_IDENTITY_CLAIMS)]
    unresolved_claims: Annotated[int, Field(ge=0, le=MAX_IDENTITY_CLAIMS)]
    same_identity_matches: Annotated[int, Field(ge=0, le=MAX_IDENTITY_MATCHES)]
    compatible_context_matches: Annotated[int, Field(ge=0, le=MAX_IDENTITY_MATCHES)]
    insufficient_evidence_matches: Annotated[int, Field(ge=0, le=MAX_IDENTITY_MATCHES)]
    conflicting_identity_matches: Annotated[int, Field(ge=0, le=MAX_IDENTITY_MATCHES)]
    not_comparable_matches: Annotated[int, Field(ge=0, le=MAX_IDENTITY_MATCHES)]
    groups: Annotated[int, Field(ge=0, le=MAX_IDENTITY_GROUPS)]
    conflicts: Annotated[int, Field(ge=0, le=MAX_IDENTITY_CONFLICTS)]
    comparisons_truncated: bool


class IdentityResolutionRequest(StrictContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    batch: EvidenceBatch


class IdentityResolutionResult(StrictContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    batch_id: Annotated[str, Field(pattern=r"^evb_[0-9a-f]{64}$")]
    rules_version: Literal["identity-rules/1.0.0"] = "identity-rules/1.0.0"
    claims: Annotated[tuple[IdentityClaim, ...], Field(max_length=MAX_IDENTITY_CLAIMS)]
    contexts: Annotated[tuple[IdentityContext, ...], Field(max_length=256)]
    matches: Annotated[
        tuple[IdentityMatchEvidence, ...], Field(max_length=MAX_IDENTITY_MATCHES)
    ]
    conflicts: Annotated[
        tuple[IdentityConflict, ...], Field(max_length=MAX_IDENTITY_CONFLICTS)
    ]
    groups: Annotated[
        tuple[ResolvedIdentityGroup, ...], Field(max_length=MAX_IDENTITY_GROUPS)
    ]
    summary: IdentityResolutionSummary
    limitations: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...],
        Field(min_length=1, max_length=16),
    ]
    persistence_performed: Literal[False] = False
    threat_correlation_performed: Literal[False] = False
    attack_finding_generated: Literal[False] = False
    risk_score_generated: Literal[False] = False
    exploitation_inferred: Literal[False] = False
    ml_promoted_to_observation: Literal[False] = False

    @model_validator(mode="after")
    def enforce_order_size_and_summary(self) -> Self:
        for claim_item in self.claims:
            IdentityClaim.model_validate(claim_item.model_dump())
        for match_item in self.matches:
            IdentityMatchEvidence.model_validate(match_item.model_dump())
        for conflict_item in self.conflicts:
            IdentityConflict.model_validate(conflict_item.model_dump())
        for group_item in self.groups:
            ResolvedIdentityGroup.model_validate(group_item.model_dump())
        if tuple(item.claim_id for item in self.claims) != tuple(
            sorted(item.claim_id for item in self.claims)
        ):
            raise ValueError("identity claims must be deterministically ordered")
        if tuple(item.evidence_id for item in self.contexts) != tuple(
            sorted(item.evidence_id for item in self.contexts)
        ):
            raise ValueError("identity contexts must be deterministically ordered")
        if tuple(item.match_id for item in self.matches) != tuple(
            sorted(item.match_id for item in self.matches)
        ):
            raise ValueError("identity matches must be deterministically ordered")
        if tuple(item.conflict_id for item in self.conflicts) != tuple(
            sorted(item.conflict_id for item in self.conflicts)
        ):
            raise ValueError("identity conflicts must be deterministically ordered")
        if tuple(item.group_id for item in self.groups) != tuple(
            sorted(item.group_id for item in self.groups)
        ):
            raise ValueError("identity groups must be deterministically ordered")
        counts = {status: 0 for status in IdentityResolutionStatus}
        for matched_item in self.matches:
            counts[matched_item.status] += 1
        expected_summary = self.summary.model_copy(
            update={
                "claims": len(self.claims),
                "resolved_claims": sum(
                    item.availability is IdentityClaimAvailability.AVAILABLE
                    for item in self.claims
                ),
                "unresolved_claims": sum(
                    item.availability is IdentityClaimAvailability.UNRESOLVED
                    for item in self.claims
                ),
                "same_identity_matches": counts[IdentityResolutionStatus.SAME_IDENTITY],
                "compatible_context_matches": counts[
                    IdentityResolutionStatus.COMPATIBLE_CONTEXT
                ],
                "insufficient_evidence_matches": counts[
                    IdentityResolutionStatus.INSUFFICIENT_EVIDENCE
                ],
                "conflicting_identity_matches": counts[
                    IdentityResolutionStatus.CONFLICTING_IDENTITY
                ],
                "not_comparable_matches": counts[
                    IdentityResolutionStatus.NOT_COMPARABLE
                ],
                "groups": len(self.groups),
                "conflicts": len(self.conflicts),
            }
        )
        if self.summary != expected_summary:
            raise ValueError("identity resolution summary is inconsistent")
        encoded = json.dumps(
            self.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode()
        if len(encoded) > MAX_IDENTITY_OUTPUT_BYTES:
            raise ValueError("identity resolution output exceeds the size limit")
        return self
