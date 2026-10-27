from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Annotated, Literal, Self, TypeAlias

from pydantic import Field, model_validator

from app.schemas.correlation import (
    CorrelationRelationshipId,
    CorrelationRelationshipType,
    CorrelationStatus,
)
from app.schemas.evidence import (
    EvidenceBatch,
    EvidenceDomain,
    EvidenceId,
    EvidenceOriginType,
    EvidenceSourceModule,
    EvidenceTrustClassification,
    EvidenceVerificationStatus,
)
from app.schemas.identity import (
    IdentityNamespace,
    IdentityResolutionStatus,
    IdentityType,
)
from app.schemas.vulnerability import StrictContract

SUFFICIENCY_SCHEMA_VERSION = "1.0.0"
MAX_ASSERTIONS_PER_REQUEST = 32
MAX_REQUIREMENTS_PER_ASSERTION = 8
MAX_EVIDENCE_REFERENCES_PER_ASSESSMENT = 16
MAX_GAPS_PER_RESULT = 256
MAX_CONTRADICTIONS_PER_RESULT = 128
MAX_UNCERTAINTY_REASONS_PER_RESULT = 256
MAX_SUFFICIENCY_EVALUATION_BUDGET = 256
MAX_SUFFICIENCY_OUTPUT_BYTES = 1024 * 1024

RequirementEvaluationId: TypeAlias = Annotated[
    str, Field(pattern=r"^sre_[0-9a-f]{64}$", max_length=68)
]
EvidenceContradictionId: TypeAlias = Annotated[
    str, Field(pattern=r"^sct_[0-9a-f]{64}$", max_length=68)
]
EvidenceGapId: TypeAlias = Annotated[
    str, Field(pattern=r"^sgp_[0-9a-f]{64}$", max_length=68)
]
UncertaintyReasonId: TypeAlias = Annotated[
    str, Field(pattern=r"^sur_[0-9a-f]{64}$", max_length=68)
]
SufficiencyAssessmentId: TypeAlias = Annotated[
    str, Field(pattern=r"^sas_[0-9a-f]{64}$", max_length=68)
]


def sufficiency_content_id(prefix: str, value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return f"{prefix}_{hashlib.sha256(encoded).hexdigest()}"


class AssertionCategory(str, Enum):
    CONTENT_IDENTITY = "content_identity"
    VULNERABILITY_IDENTITY = "vulnerability_identity"
    ANALYSIS_CONTEXT = "analysis_context"
    EXPLICIT_REFERENCE = "explicit_reference"


class SufficiencyState(str, Enum):
    SUFFICIENT = "sufficient"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    CONFLICTING_EVIDENCE = "conflicting_evidence"
    NOT_APPLICABLE = "not_applicable"
    UNSUPPORTED_ASSERTION = "unsupported_assertion"


class RequirementKind(str, Enum):
    EVIDENCE_RECORD_EXISTS = "evidence_record_exists"
    PROVENANCE_AVAILABLE = "provenance_available"
    IDENTITY_SATISFIED = "identity_satisfied"
    CORRELATION_SUPPORTED = "correlation_supported"
    NO_RELEVANT_CONFLICT = "no_relevant_conflict"


class RequirementState(str, Enum):
    SATISFIED = "satisfied"
    MISSING = "missing"
    CONFLICTING = "conflicting"
    NOT_APPLICABLE = "not_applicable"


class EvidenceGapCategory(str, Enum):
    MISSING_RECORD = "missing_record"
    MISSING_IDENTITY = "missing_identity"
    MISSING_RELATIONSHIP = "missing_relationship"
    MISSING_PROVENANCE = "missing_provenance"
    INAPPLICABLE_DOMAIN = "inapplicable_domain"


class ContradictionCategory(str, Enum):
    IDENTITY_CONFLICT = "identity_conflict"
    CORRELATION_CONFLICT = "correlation_conflict"
    DUPLICATE_REFERENCE = "duplicate_reference"


class UncertaintyCategory(str, Enum):
    MISSING_IDENTITY = "missing_identity"
    UNVERIFIED_PROVENANCE = "unverified_provenance"
    SYNTHETIC_ORIGIN = "synthetic_origin"
    DECLARED_CONTEXT = "declared_context"
    MISSING_MODEL_VERSION = "missing_model_version"
    MISSING_TEMPORAL_CONTEXT = "missing_temporal_context"
    WEAK_CONTEXTUAL_ASSOCIATION = "weak_contextual_association"
    UNSUPPORTED_CROSS_MODULE_RELATION = "unsupported_cross_module_relation"
    CONFLICTING_CLAIMS = "conflicting_claims"
    INCOMPLETE_SOURCE_METADATA = "incomplete_source_metadata"


class EvidenceRequirement(StrictContract):
    requirement_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")]
    kind: RequirementKind
    description: Annotated[str, Field(min_length=1, max_length=256)]
    required: bool


class SufficiencyAssertion(StrictContract):
    assertion_id: Annotated[str, Field(pattern=r"^AS-[A-Z]+-[0-9]{3}$", max_length=32)]
    version: Literal["1.0.0"] = "1.0.0"
    category: AssertionCategory
    statement: Annotated[str, Field(min_length=1, max_length=256)]
    applicable_domains: Annotated[
        tuple[EvidenceDomain, ...], Field(min_length=1, max_length=4)
    ]
    required_evidence_types: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=64)], ...],
        Field(min_length=1, max_length=4),
    ]
    required_identity_type: IdentityType | None
    required_identity_namespace: IdentityNamespace | None
    required_identity_status: IdentityResolutionStatus | None
    required_relationship_type: CorrelationRelationshipType
    required_correlation_status: Literal[CorrelationStatus.SUPPORTED] = (
        CorrelationStatus.SUPPORTED
    )
    required_provenance: Literal["available_and_preserved"] = "available_and_preserved"
    requirements: Annotated[
        tuple[EvidenceRequirement, ...],
        Field(min_length=1, max_length=MAX_REQUIREMENTS_PER_ASSERTION),
    ]
    contradiction_conditions: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=256)], ...],
        Field(min_length=1, max_length=8),
    ]
    limitations: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...],
        Field(min_length=1, max_length=8),
    ]
    safe_explanation_template: Annotated[str, Field(min_length=1, max_length=512)]
    executable_expression: Literal[False] = False
    confidence_score_defined: Literal[False] = False

    @model_validator(mode="after")
    def validate_policy(self) -> Self:
        requirement_ids = tuple(item.requirement_id for item in self.requirements)
        if len(requirement_ids) != len(set(requirement_ids)):
            raise ValueError("assertion requirement identifiers must be unique")
        if (self.required_identity_type is None) != (
            self.required_identity_namespace is None
        ):
            raise ValueError("identity type and namespace must be declared together")
        return self


class AssertionSelection(StrictContract):
    assertion_id: Annotated[str, Field(pattern=r"^AS-[A-Z]+-[0-9]{3}$", max_length=32)]
    evidence_ids: Annotated[
        tuple[EvidenceId, ...],
        Field(min_length=1, max_length=MAX_EVIDENCE_REFERENCES_PER_ASSESSMENT),
    ]

    @model_validator(mode="after")
    def validate_selection(self) -> Self:
        if self.evidence_ids != tuple(sorted(set(self.evidence_ids))):
            raise ValueError("selected evidence IDs must be unique and sorted")
        return self


class EvidenceSupportReference(StrictContract):
    evidence_id: EvidenceId
    source_module: EvidenceSourceModule
    origin_type: EvidenceOriginType
    trust_classification: EvidenceTrustClassification
    synthetic: bool
    verification_status: EvidenceVerificationStatus
    relationship_id: CorrelationRelationshipId | None = None
    safe_categories: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=64)], ...],
        Field(min_length=1, max_length=8),
    ]
    raw_value_disclosed: Literal[False] = False


class RequirementEvaluation(StrictContract):
    evaluation_id: RequirementEvaluationId
    requirement_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")]
    state: RequirementState
    supporting_evidence_ids: Annotated[
        tuple[EvidenceId, ...], Field(max_length=MAX_EVIDENCE_REFERENCES_PER_ASSESSMENT)
    ] = ()
    supporting_relationship_ids: Annotated[
        tuple[CorrelationRelationshipId, ...], Field(max_length=4)
    ] = ()
    explanation: Annotated[str, Field(min_length=1, max_length=512)]

    @model_validator(mode="after")
    def verify_identifier(self) -> Self:
        material = {
            "requirement_id": self.requirement_id,
            "state": self.state.value,
            "evidence_ids": self.supporting_evidence_ids,
            "relationship_ids": self.supporting_relationship_ids,
        }
        if self.evaluation_id != sufficiency_content_id("sre", material):
            raise ValueError(
                "requirement evaluation ID does not match canonical content"
            )
        return self


class EvidenceContradiction(StrictContract):
    contradiction_id: EvidenceContradictionId
    category: ContradictionCategory
    assertion_id: Annotated[str, Field(pattern=r"^AS-[A-Z]+-[0-9]{3}$")]
    requirement_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")]
    evidence_ids: Annotated[tuple[EvidenceId, ...], Field(min_length=1, max_length=256)]
    identity_namespace: IdentityNamespace | None
    source_conflict_id: Annotated[str, Field(pattern=r"^(?:idf|crf)_[0-9a-f]{64}$")]
    explanation: Annotated[str, Field(min_length=1, max_length=512)]
    source_precedence_applied: Literal[False] = False

    @model_validator(mode="after")
    def verify_identifier(self) -> Self:
        material = {
            "category": self.category.value,
            "assertion_id": self.assertion_id,
            "requirement_id": self.requirement_id,
            "evidence_ids": self.evidence_ids,
            "namespace": None
            if self.identity_namespace is None
            else self.identity_namespace.value,
            "source_conflict_id": self.source_conflict_id,
        }
        if self.contradiction_id != sufficiency_content_id("sct", material):
            raise ValueError("contradiction ID does not match canonical content")
        return self


class EvidenceGap(StrictContract):
    gap_id: EvidenceGapId
    category: EvidenceGapCategory
    assertion_id: Annotated[str, Field(pattern=r"^AS-[A-Z]+-[0-9]{3}$")]
    requirement_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")]
    missing_evidence_ids: Annotated[tuple[EvidenceId, ...], Field(max_length=16)] = ()
    explanation: Annotated[str, Field(min_length=1, max_length=512)]
    assertion_proven_false: Literal[False] = False

    @model_validator(mode="after")
    def verify_identifier(self) -> Self:
        material = {
            "category": self.category.value,
            "assertion_id": self.assertion_id,
            "requirement_id": self.requirement_id,
            "missing_evidence_ids": self.missing_evidence_ids,
        }
        if self.gap_id != sufficiency_content_id("sgp", material):
            raise ValueError("gap ID does not match canonical content")
        return self


class UncertaintyReason(StrictContract):
    uncertainty_id: UncertaintyReasonId
    category: UncertaintyCategory
    assertion_id: Annotated[str, Field(pattern=r"^AS-[A-Z]+-[0-9]{3}$")]
    evidence_ids: Annotated[tuple[EvidenceId, ...], Field(max_length=16)] = ()
    explanation: Annotated[str, Field(min_length=1, max_length=512)]
    affects_sufficiency: bool
    numeric_confidence: Literal[None] = None

    @model_validator(mode="after")
    def verify_identifier(self) -> Self:
        material = {
            "category": self.category.value,
            "assertion_id": self.assertion_id,
            "evidence_ids": self.evidence_ids,
            "affects_sufficiency": self.affects_sufficiency,
        }
        if self.uncertainty_id != sufficiency_content_id("sur", material):
            raise ValueError("uncertainty ID does not match canonical content")
        return self


class SufficiencyAssessment(StrictContract):
    assessment_id: SufficiencyAssessmentId
    assertion_id: Annotated[str, Field(pattern=r"^AS-[A-Z]+-[0-9]{3}$")]
    assertion_version: Annotated[
        str | None, Field(default=None, pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    ]
    statement: Annotated[str, Field(min_length=1, max_length=256)]
    state: SufficiencyState
    evidence_ids: Annotated[tuple[EvidenceId, ...], Field(min_length=1, max_length=16)]
    requirement_evaluations: Annotated[
        tuple[RequirementEvaluation, ...],
        Field(max_length=MAX_REQUIREMENTS_PER_ASSERTION),
    ]
    support_references: Annotated[
        tuple[EvidenceSupportReference, ...],
        Field(max_length=MAX_EVIDENCE_REFERENCES_PER_ASSESSMENT),
    ]
    contradictions: Annotated[tuple[EvidenceContradiction, ...], Field(max_length=16)]
    gaps: Annotated[tuple[EvidenceGap, ...], Field(max_length=16)]
    uncertainty_reasons: Annotated[tuple[UncertaintyReason, ...], Field(max_length=32)]
    limitations: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...],
        Field(min_length=1, max_length=8),
    ]
    universal_certainty_claimed: Literal[False] = False
    threat_confirmed: Literal[False] = False

    @model_validator(mode="after")
    def verify_identifier_and_state(self) -> Self:
        material = {
            "assertion_id": self.assertion_id,
            "assertion_version": self.assertion_version,
            "evidence_ids": self.evidence_ids,
            "state": self.state.value,
            "requirements": tuple(
                item.evaluation_id for item in self.requirement_evaluations
            ),
            "contradictions": tuple(
                item.contradiction_id for item in self.contradictions
            ),
            "gaps": tuple(item.gap_id for item in self.gaps),
            "uncertainties": tuple(
                item.uncertainty_id for item in self.uncertainty_reasons
            ),
        }
        if self.assessment_id != sufficiency_content_id("sas", material):
            raise ValueError("assessment ID does not match canonical content")
        if self.state is SufficiencyState.SUFFICIENT:
            if (
                any(
                    item.state is not RequirementState.SATISFIED
                    for item in self.requirement_evaluations
                )
                or self.contradictions
                or self.gaps
            ):
                raise ValueError(
                    "sufficient assessment requires all requirements without gaps or contradictions"
                )
        return self


class SufficiencyAssessmentRequest(StrictContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    batch: EvidenceBatch
    assertions: Annotated[
        tuple[AssertionSelection, ...],
        Field(min_length=1, max_length=MAX_ASSERTIONS_PER_REQUEST),
    ]

    @model_validator(mode="after")
    def enforce_budget_and_uniqueness(self) -> Self:
        keys = tuple((item.assertion_id, item.evidence_ids) for item in self.assertions)
        if len(keys) != len(set(keys)):
            raise ValueError("assertion selections must be unique")
        if (
            len(self.assertions) * MAX_REQUIREMENTS_PER_ASSERTION
            > MAX_SUFFICIENCY_EVALUATION_BUDGET
        ):
            raise ValueError("assertion request exceeds the evaluation budget")
        return self


class SufficiencySummary(StrictContract):
    evidence_records: Annotated[int, Field(ge=1, le=256)]
    requested_assertions: Annotated[int, Field(ge=1, le=MAX_ASSERTIONS_PER_REQUEST)]
    sufficient: Annotated[int, Field(ge=0, le=MAX_ASSERTIONS_PER_REQUEST)]
    insufficient_evidence: Annotated[int, Field(ge=0, le=MAX_ASSERTIONS_PER_REQUEST)]
    conflicting_evidence: Annotated[int, Field(ge=0, le=MAX_ASSERTIONS_PER_REQUEST)]
    not_applicable: Annotated[int, Field(ge=0, le=MAX_ASSERTIONS_PER_REQUEST)]
    unsupported_assertion: Annotated[int, Field(ge=0, le=MAX_ASSERTIONS_PER_REQUEST)]
    gaps: Annotated[int, Field(ge=0, le=MAX_GAPS_PER_RESULT)]
    contradictions: Annotated[int, Field(ge=0, le=MAX_CONTRADICTIONS_PER_RESULT)]
    uncertainty_reasons: Annotated[
        int, Field(ge=0, le=MAX_UNCERTAINTY_REASONS_PER_RESULT)
    ]
    limits_reached: bool


class SufficiencyAssessmentResult(StrictContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    batch_id: Annotated[str, Field(pattern=r"^evb_[0-9a-f]{64}$")]
    policy_version: Literal["sufficiency-assertions/1.0.0"] = (
        "sufficiency-assertions/1.0.0"
    )
    identity_rules_version: Literal["identity-rules/1.0.0"] = "identity-rules/1.0.0"
    correlation_rules_version: Literal["correlation-rules/1.0.0"] = (
        "correlation-rules/1.0.0"
    )
    assessments: Annotated[
        tuple[SufficiencyAssessment, ...], Field(max_length=MAX_ASSERTIONS_PER_REQUEST)
    ]
    summary: SufficiencySummary
    limitations: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...],
        Field(min_length=1, max_length=16),
    ]
    persistence_performed: Literal[False] = False
    causal_inference_performed: Literal[False] = False
    temporal_sequence_inferred: Literal[False] = False
    threat_confirmed: Literal[False] = False
    malware_detected: Literal[False] = False
    host_compromised: Literal[False] = False
    exploitation_inferred: Literal[False] = False
    attack_technique_executed: Literal[False] = False
    file_executed: Literal[False] = False
    risk_score_generated: Literal[False] = False
    probability_generated: Literal[False] = False
    trust_promoted: Literal[False] = False

    @model_validator(mode="after")
    def enforce_result_invariants(self) -> Self:
        identifiers = tuple(item.assessment_id for item in self.assessments)
        if identifiers != tuple(sorted(identifiers)):
            raise ValueError("assessments must be deterministically ordered")
        counts = {state: 0 for state in SufficiencyState}
        for assessment in self.assessments:
            counts[assessment.state] += 1
        expected = self.summary.model_copy(
            update={
                "requested_assertions": len(self.assessments),
                "sufficient": counts[SufficiencyState.SUFFICIENT],
                "insufficient_evidence": counts[SufficiencyState.INSUFFICIENT_EVIDENCE],
                "conflicting_evidence": counts[SufficiencyState.CONFLICTING_EVIDENCE],
                "not_applicable": counts[SufficiencyState.NOT_APPLICABLE],
                "unsupported_assertion": counts[SufficiencyState.UNSUPPORTED_ASSERTION],
                "gaps": sum(len(item.gaps) for item in self.assessments),
                "contradictions": sum(
                    len(item.contradictions) for item in self.assessments
                ),
                "uncertainty_reasons": sum(
                    len(item.uncertainty_reasons) for item in self.assessments
                ),
            }
        )
        if self.summary != expected:
            raise ValueError("sufficiency summary is inconsistent")
        encoded = json.dumps(
            self.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode()
        if len(encoded) > MAX_SUFFICIENCY_OUTPUT_BYTES:
            raise ValueError("sufficiency output exceeds the size limit")
        return self
