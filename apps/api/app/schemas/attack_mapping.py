from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal, Self, TypeAlias
from uuid import UUID

from pydantic import Field, model_validator

from app.schemas.attack import ATTACKObjectStatus, ATTACKProvenance
from app.schemas.behavior import EventBatch, EventNature, EventPlatform
from app.schemas.behavior_correlation import CorrelationPolicy, CorrelationSummary
from app.schemas.behavior_rules import (
    RuleEvaluationSummary,
    RuleEventFamily,
    RuleIdentifier,
)
from app.schemas.vulnerability import StrictContract

MAPPING_SCHEMA_VERSION = "1.0.0"
MAX_MAPPING_POLICIES = 16
MAX_MAPPING_EVALUATIONS = 16
MAX_EVIDENCE_REFERENCES = 16
MAX_REFERENCE_EVENT_IDS = 8
MAX_MAPPING_OUTPUT_BYTES = 512 * 1024
MAPPING_EVALUATION_DEADLINE_SECONDS = 1.0
MAPPING_OPERATION_TIMEOUT_SECONDS = 2.0
MAPPING_MAX_CONCURRENCY = 4

AttackMappingPolicyIdentifier: TypeAlias = Annotated[
    str, Field(pattern=r"^AMP-(?:PROC|NET|CONF)-[0-9]{3}$", max_length=16)
]


class MappingState(str, Enum):
    CANDIDATE = "candidate"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    NOT_SUPPORTED = "not_supported"
    NOT_APPLICABLE = "not_applicable"
    CATALOG_UNAVAILABLE = "catalog_unavailable"
    RETIRED_TECHNIQUE = "retired_technique"


class MappingEvidenceType(str, Enum):
    DECLARED_EVENT = "declared_event"
    RULE_FINDING = "rule_finding"
    TEMPORAL_RELATIONSHIP = "temporal_relationship"
    SCHEMA_CAPABILITY = "schema_capability"


class MappingEvidenceStrength(str, Enum):
    STRONG = "strong"
    WEAK = "weak"
    INDETERMINATE = "indeterminate"


class MappingEvidenceRequirement(StrictContract):
    requirement_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")]
    evidence_type: MappingEvidenceType
    evidence_key: Annotated[str, Field(min_length=1, max_length=128)]
    description: Annotated[str, Field(min_length=1, max_length=512)]
    required: bool = True


class AttackMappingPolicy(StrictContract):
    policy_id: AttackMappingPolicyIdentifier
    version: Annotated[str, Field(pattern=r"^[1-9][0-9]*\.[0-9]+\.[0-9]+$")]
    technique_id: Annotated[str, Field(pattern=r"^T\d{4}(?:\.\d{3})?$")]
    purpose: Annotated[str, Field(min_length=1, max_length=1024)]
    applicable_family: RuleEventFamily
    applicable_platforms: Annotated[
        tuple[EventPlatform, ...], Field(min_length=1, max_length=3)
    ]
    required_rule_id: RuleIdentifier
    minimum_evidence: Annotated[
        tuple[MappingEvidenceRequirement, ...], Field(min_length=1, max_length=8)
    ]
    optional_evidence: Annotated[
        tuple[MappingEvidenceRequirement, ...], Field(max_length=8)
    ] = ()
    contradictory_conditions: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=256)], ...],
        Field(max_length=8),
    ] = ()
    limitations: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...],
        Field(min_length=1, max_length=8),
    ]
    retired_policy: Literal["report_never_candidate"] = "report_never_candidate"

    @model_validator(mode="after")
    def validate_requirements(self) -> Self:
        requirements = self.minimum_evidence + self.optional_evidence
        identities = [item.requirement_id for item in requirements]
        if len(identities) != len(set(identities)):
            raise ValueError("mapping requirement IDs must be unique")
        if not all(item.required for item in self.minimum_evidence):
            raise ValueError("minimum evidence must be required")
        return self


class MappingEvidenceReference(StrictContract):
    evidence_type: MappingEvidenceType
    reference_id: Annotated[str, Field(min_length=1, max_length=128)]
    event_ids: Annotated[tuple[UUID, ...], Field(max_length=MAX_REFERENCE_EVENT_IDS)]
    nature: Annotated[tuple[EventNature, ...], Field(max_length=2)]
    strength: MappingEvidenceStrength
    backend_generated: Literal[True] = True
    facts: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=256)], ...],
        Field(min_length=1, max_length=8),
    ]


class MappingCandidate(StrictContract):
    attack_id: Annotated[str, Field(pattern=r"^T\d{4}(?:\.\d{3})?$")]
    stix_id: Annotated[str, Field(pattern=r"^attack-pattern--[0-9a-f-]{36}$")]
    name: Annotated[str, Field(min_length=1, max_length=512)]
    parent_attack_id: Annotated[str | None, Field(default=None, pattern=r"^T\d{4}$")]
    is_subtechnique: bool
    tactic_ids: tuple[Annotated[str, Field(pattern=r"^TA\d{4}$")], ...]
    platforms: tuple[Annotated[str, Field(min_length=1, max_length=128)], ...]
    status: ATTACKObjectStatus
    domain: Literal["enterprise-attack"]
    catalog_version: Annotated[str, Field(pattern=r"^\d+\.\d+$")]
    official_references: Annotated[
        tuple[Annotated[str, Field(pattern=r"^https://", max_length=4096)], ...],
        Field(max_length=8),
    ]


class MappingExplanation(StrictContract):
    template_id: Literal["attack_mapping_assessment_v1"] = (
        "attack_mapping_assessment_v1"
    )
    assessment: Annotated[str, Field(min_length=1, max_length=512)]
    satisfied_conditions: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...],
        Field(max_length=16),
    ]
    missing_conditions: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...],
        Field(max_length=16),
    ]
    contradictory_conditions: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...],
        Field(max_length=16),
    ]
    declared_information: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...],
        Field(max_length=16),
    ]
    catalog_information: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...],
        Field(max_length=16),
    ]
    scientific_boundary: Literal[
        "An educational candidate is not confirmation of adversary behavior, malicious activity, compromise, attribution, or malware."
    ] = "An educational candidate is not confirmation of adversary behavior, malicious activity, compromise, attribution, or malware."


class MappingEvaluation(StrictContract):
    policy_id: AttackMappingPolicyIdentifier
    policy_version: str
    state: MappingState
    technique: MappingCandidate | None
    conditions_evaluated: tuple[
        Annotated[str, Field(min_length=1, max_length=512)], ...
    ]
    positive_evidence: Annotated[
        tuple[MappingEvidenceReference, ...], Field(max_length=MAX_EVIDENCE_REFERENCES)
    ]
    missing_evidence: tuple[Annotated[str, Field(min_length=1, max_length=512)], ...]
    contradictory_evidence: tuple[
        Annotated[str, Field(min_length=1, max_length=512)], ...
    ]
    explanation: MappingExplanation
    limitations: tuple[Annotated[str, Field(min_length=1, max_length=512)], ...]


class AttackMappingSummary(StrictContract):
    evaluated_policies: int
    candidates: int
    insufficient_evidence: int
    not_supported: int
    not_applicable: int
    catalog_unavailable: int
    retired_technique: int
    evidence_references: int
    evaluations_truncated: bool


class AttackMappingRequest(StrictContract):
    batch: EventBatch
    policy_ids: Annotated[
        tuple[AttackMappingPolicyIdentifier, ...] | None,
        Field(default=None, min_length=1, max_length=MAX_MAPPING_POLICIES),
    ]
    correlation_policy: CorrelationPolicy = Field(default_factory=CorrelationPolicy)

    @model_validator(mode="after")
    def reject_duplicate_policies(self) -> Self:
        if self.policy_ids is not None and len(set(self.policy_ids)) != len(
            self.policy_ids
        ):
            raise ValueError("policy_ids must not contain duplicates")
        return self


class AttackMappingAssessment(StrictContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    catalog_provenance: ATTACKProvenance | None
    rule_evaluation_summary: RuleEvaluationSummary
    temporal_correlation_summary: CorrelationSummary
    evaluations: Annotated[
        tuple[MappingEvaluation, ...], Field(max_length=MAX_MAPPING_EVALUATIONS)
    ]
    summary: AttackMappingSummary
    limitations: tuple[Annotated[str, Field(min_length=1, max_length=512)], ...]
    backend_evidence_recomputed: Literal[True] = True
    confirmed_attack: Literal[False] = False
    malicious_activity_confirmed: Literal[False] = False
    malware_detected: Literal[False] = False
    attribution_performed: Literal[False] = False
    vulnerability_mapping_performed: Literal[False] = False
    persisted: Literal[False] = False


class AttackMappingPolicyRegistryResponse(StrictContract):
    policies: tuple[AttackMappingPolicy, ...]
    count: int
    catalog_available: bool
    catalog_version: str | None
    registry_immutable: Literal[True] = True
    client_definitions_accepted: Literal[False] = False
