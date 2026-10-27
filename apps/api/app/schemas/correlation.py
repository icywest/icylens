from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Annotated, Literal, Self, TypeAlias

from pydantic import Field, model_validator

from app.schemas.evidence import (
    EvidenceBatch,
    EvidenceId,
    EvidenceOriginType,
    EvidenceSourceModule,
    EvidenceTrustClassification,
    EvidenceVerificationStatus,
)
from app.schemas.identity import (
    IdentityConflictId,
    IdentityMatchId,
    IdentityNamespace,
    IdentityType,
    ResolvedIdentityGroupId,
)
from app.schemas.vulnerability import StrictContract

CORRELATION_SCHEMA_VERSION = "1.0.0"
MAX_CORRELATION_CANDIDATES = 512
MAX_CORRELATION_EVALUATIONS = 512
MAX_CORRELATION_RELATIONSHIPS = 256
MAX_CORRELATION_CONFLICTS = 256
MAX_CORRELATION_GRAPH_EDGES = 512
MAX_CORRELATION_EVIDENCE_REFERENCES = 256
MAX_CORRELATION_OUTPUT_BYTES = 1024 * 1024

CorrelationCandidateId: TypeAlias = Annotated[
    str, Field(pattern=r"^crc_[0-9a-f]{64}$", max_length=68)
]
CorrelationEvaluationId: TypeAlias = Annotated[
    str, Field(pattern=r"^cre_[0-9a-f]{64}$", max_length=68)
]
CorrelationRelationshipId: TypeAlias = Annotated[
    str, Field(pattern=r"^crr_[0-9a-f]{64}$", max_length=68)
]
CorrelationConflictId: TypeAlias = Annotated[
    str, Field(pattern=r"^crf_[0-9a-f]{64}$", max_length=68)
]
CorrelationEdgeId: TypeAlias = Annotated[
    str, Field(pattern=r"^crg_[0-9a-f]{64}$", max_length=68)
]


def correlation_content_id(prefix: str, value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return f"{prefix}_{hashlib.sha256(encoded).hexdigest()}"


class CorrelationStatus(str, Enum):
    SUPPORTED = "supported"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    CONFLICTING_EVIDENCE = "conflicting_evidence"
    NOT_APPLICABLE = "not_applicable"
    UNSUPPORTED_RELATION = "unsupported_relation"


class CorrelationRelationshipType(str, Enum):
    SHARED_CONTENT_IDENTITY = "shared_content_identity"
    SHARED_VULNERABILITY_IDENTITY = "shared_vulnerability_identity"
    SHARED_ANALYSIS_CONTEXT = "shared_analysis_context"
    EXPLICIT_EVIDENCE_REFERENCE = "explicit_evidence_reference"


class CorrelationRequirementKind(str, Enum):
    IDENTITY_GROUP = "identity_group"
    EXPLICIT_REFERENCE = "explicit_reference"
    PROVENANCE_PRESERVED = "provenance_preserved"
    NO_IDENTITY_CONFLICT = "no_identity_conflict"


class CorrelationRequirementStatus(str, Enum):
    SATISFIED = "satisfied"
    MISSING = "missing"
    CONTRADICTORY = "contradictory"
    NOT_APPLICABLE = "not_applicable"


class CorrelationCandidateSource(str, Enum):
    IDENTITY_GROUP = "identity_group"
    IDENTITY_MATCH = "identity_match"
    EXPLICIT_REFERENCE = "explicit_reference"


class CorrelationRequirement(StrictContract):
    requirement_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")]
    kind: CorrelationRequirementKind
    description: Annotated[str, Field(min_length=1, max_length=256)]
    required: bool


class CorrelationRule(StrictContract):
    rule_id: Annotated[str, Field(pattern=r"^CR-[A-Z]+-[0-9]{3}$", max_length=32)]
    version: Literal["1.0.0"] = "1.0.0"
    relationship_type: CorrelationRelationshipType | None
    identity_type: IdentityType | None
    allowed_namespaces: Annotated[tuple[IdentityNamespace, ...], Field(max_length=4)]
    applicable_candidate_sources: Annotated[
        tuple[CorrelationCandidateSource, ...], Field(min_length=1, max_length=3)
    ]
    requirements: Annotated[
        tuple[CorrelationRequirement, ...], Field(min_length=1, max_length=8)
    ]
    explanation_template: Annotated[str, Field(min_length=1, max_length=512)]
    limitations: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...],
        Field(min_length=1, max_length=8),
    ]
    dynamic_expression: Literal[False] = False
    score_generated: Literal[False] = False


class CorrelationCandidate(StrictContract):
    candidate_id: CorrelationCandidateId
    rule_id: Annotated[str, Field(pattern=r"^CR-[A-Z]+-[0-9]{3}$", max_length=32)]
    source: CorrelationCandidateSource
    evidence_ids: Annotated[tuple[EvidenceId, ...], Field(min_length=1, max_length=256)]
    identity_type: IdentityType | None = None
    namespace: IdentityNamespace | None = None
    identity_group_id: ResolvedIdentityGroupId | None = None
    identity_match_id: IdentityMatchId | None = None
    reference_source_id: EvidenceId | None = None
    reference_target_id: EvidenceId | None = None
    reference_type: Annotated[str | None, Field(default=None, max_length=64)]

    @model_validator(mode="after")
    def verify_candidate(self) -> Self:
        if self.evidence_ids != tuple(sorted(set(self.evidence_ids))):
            raise ValueError("candidate evidence IDs must be unique and sorted")
        material = {
            "rule_id": self.rule_id,
            "source": self.source.value,
            "evidence_ids": self.evidence_ids,
            "identity_type": None
            if self.identity_type is None
            else self.identity_type.value,
            "namespace": None if self.namespace is None else self.namespace.value,
            "identity_group_id": self.identity_group_id,
            "identity_match_id": self.identity_match_id,
            "reference_source_id": self.reference_source_id,
            "reference_target_id": self.reference_target_id,
            "reference_type": self.reference_type,
        }
        if self.candidate_id != correlation_content_id("crc", material):
            raise ValueError("candidate ID does not match canonical content")
        return self


class CorrelationEvidenceReference(StrictContract):
    evidence_id: EvidenceId
    source_module: EvidenceSourceModule
    source_phase: Literal["02", "03", "04", "05"]
    origin_type: EvidenceOriginType
    trust_classification: EvidenceTrustClassification
    synthetic: bool
    verification_status: EvidenceVerificationStatus
    field_categories: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=64)], ...],
        Field(min_length=1, max_length=8),
    ]
    raw_content_disclosed: Literal[False] = False


class CorrelationRequirementEvaluation(StrictContract):
    requirement_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")]
    status: CorrelationRequirementStatus
    explanation: Annotated[str, Field(min_length=1, max_length=512)]


class CorrelationEvaluation(StrictContract):
    evaluation_id: CorrelationEvaluationId
    candidate_id: CorrelationCandidateId
    rule_id: Annotated[str, Field(pattern=r"^CR-[A-Z]+-[0-9]{3}$", max_length=32)]
    status: CorrelationStatus
    requirement_evaluations: Annotated[
        tuple[CorrelationRequirementEvaluation, ...], Field(min_length=1, max_length=8)
    ]
    identity_conflict_ids: Annotated[
        tuple[IdentityConflictId, ...], Field(max_length=16)
    ] = ()
    explanation: Annotated[str, Field(min_length=1, max_length=512)]
    limitations: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...],
        Field(min_length=1, max_length=8),
    ]
    relationship_supported: bool
    score_generated: Literal[False] = False

    @model_validator(mode="after")
    def verify_evaluation(self) -> Self:
        if self.relationship_supported != (self.status is CorrelationStatus.SUPPORTED):
            raise ValueError("only supported evaluations can support relationships")
        material = {
            "candidate_id": self.candidate_id,
            "rule_id": self.rule_id,
            "status": self.status.value,
            "requirements": tuple(
                (item.requirement_id, item.status.value)
                for item in self.requirement_evaluations
            ),
            "conflicts": self.identity_conflict_ids,
        }
        if self.evaluation_id != correlation_content_id("cre", material):
            raise ValueError("evaluation ID does not match canonical content")
        return self


class CorrelationConflict(StrictContract):
    conflict_id: CorrelationConflictId
    source_identity_conflict_id: IdentityConflictId
    evidence_ids: Annotated[tuple[EvidenceId, ...], Field(min_length=1, max_length=256)]
    field_categories: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=64)], ...],
        Field(min_length=1, max_length=8),
    ]
    explanation: Annotated[str, Field(min_length=1, max_length=512)]
    source_precedence_applied: Literal[False] = False
    conflict_suppressed: Literal[False] = False

    @model_validator(mode="after")
    def verify_conflict(self) -> Self:
        material = {
            "source_identity_conflict_id": self.source_identity_conflict_id,
            "evidence_ids": self.evidence_ids,
            "fields": self.field_categories,
        }
        if self.conflict_id != correlation_content_id("crf", material):
            raise ValueError("correlation conflict ID does not match canonical content")
        return self


class CorrelationRelationship(StrictContract):
    relationship_id: CorrelationRelationshipId
    rule_id: Annotated[str, Field(pattern=r"^CR-[A-Z]+-[0-9]{3}$", max_length=32)]
    evaluation_id: CorrelationEvaluationId
    relationship_type: CorrelationRelationshipType
    evidence_ids: Annotated[tuple[EvidenceId, ...], Field(min_length=2, max_length=256)]
    identity_type: IdentityType | None = None
    namespace: IdentityNamespace | None = None
    supporting_identity_group_id: ResolvedIdentityGroupId | None = None
    supporting_identity_match_ids: Annotated[
        tuple[IdentityMatchId, ...], Field(max_length=16)
    ] = ()
    evidence_references: Annotated[
        tuple[CorrelationEvidenceReference, ...],
        Field(min_length=2, max_length=MAX_CORRELATION_EVIDENCE_REFERENCES),
    ]
    limitations: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...],
        Field(min_length=1, max_length=8),
    ]
    status: Literal[CorrelationStatus.SUPPORTED] = CorrelationStatus.SUPPORTED
    causal_relationship_inferred: Literal[False] = False
    temporal_sequence_inferred: Literal[False] = False
    threat_verdict_generated: Literal[False] = False
    trust_promoted: Literal[False] = False

    @model_validator(mode="after")
    def verify_relationship(self) -> Self:
        if self.evidence_ids != tuple(sorted(set(self.evidence_ids))):
            raise ValueError("relationship evidence IDs must be unique and sorted")
        if (
            tuple(item.evidence_id for item in self.evidence_references)
            != self.evidence_ids
        ):
            raise ValueError("relationship references must exactly cover evidence IDs")
        material = {
            "rule_id": self.rule_id,
            "evaluation_id": self.evaluation_id,
            "relationship_type": self.relationship_type.value,
            "evidence_ids": self.evidence_ids,
            "identity_group_id": self.supporting_identity_group_id,
            "identity_match_ids": self.supporting_identity_match_ids,
        }
        if self.relationship_id != correlation_content_id("crr", material):
            raise ValueError("relationship ID does not match canonical content")
        return self


class CorrelationGraphNode(StrictContract):
    node_id: EvidenceId
    evidence_id: EvidenceId
    source_module: EvidenceSourceModule
    origin_type: EvidenceOriginType
    trust_classification: EvidenceTrustClassification
    synthetic: bool
    raw_content_disclosed: Literal[False] = False

    @model_validator(mode="after")
    def verify_node(self) -> Self:
        if self.node_id != self.evidence_id:
            raise ValueError("graph node ID must equal its evidence ID")
        return self


class CorrelationGraphEdge(StrictContract):
    edge_id: CorrelationEdgeId
    relationship_id: CorrelationRelationshipId
    rule_id: Annotated[str, Field(pattern=r"^CR-[A-Z]+-[0-9]{3}$", max_length=32)]
    relationship_type: CorrelationRelationshipType
    source_node_id: EvidenceId
    target_node_id: EvidenceId
    evidence_references: Annotated[
        tuple[EvidenceId, EvidenceId], Field(min_length=2, max_length=2)
    ]
    direct_rule_support: Literal[True] = True
    transitive_inference: Literal[False] = False

    @model_validator(mode="after")
    def verify_edge(self) -> Self:
        if self.source_node_id >= self.target_node_id:
            raise ValueError("graph edge nodes must be distinct and ordered")
        if self.evidence_references != (self.source_node_id, self.target_node_id):
            raise ValueError("edge references must equal its ordered endpoints")
        material = {
            "relationship_id": self.relationship_id,
            "rule_id": self.rule_id,
            "relationship_type": self.relationship_type.value,
            "source": self.source_node_id,
            "target": self.target_node_id,
        }
        if self.edge_id != correlation_content_id("crg", material):
            raise ValueError("graph edge ID does not match canonical content")
        return self


class CorrelationSummary(StrictContract):
    evidence_records: Annotated[int, Field(ge=1, le=256)]
    candidates: Annotated[int, Field(ge=0, le=MAX_CORRELATION_CANDIDATES)]
    evaluations: Annotated[int, Field(ge=0, le=MAX_CORRELATION_EVALUATIONS)]
    supported: Annotated[int, Field(ge=0, le=MAX_CORRELATION_EVALUATIONS)]
    insufficient_evidence: Annotated[int, Field(ge=0, le=MAX_CORRELATION_EVALUATIONS)]
    conflicting_evidence: Annotated[int, Field(ge=0, le=MAX_CORRELATION_EVALUATIONS)]
    not_applicable: Annotated[int, Field(ge=0, le=MAX_CORRELATION_EVALUATIONS)]
    unsupported_relation: Annotated[int, Field(ge=0, le=MAX_CORRELATION_EVALUATIONS)]
    relationships: Annotated[int, Field(ge=0, le=MAX_CORRELATION_RELATIONSHIPS)]
    conflicts: Annotated[int, Field(ge=0, le=MAX_CORRELATION_CONFLICTS)]
    graph_nodes: Annotated[int, Field(ge=1, le=256)]
    graph_edges: Annotated[int, Field(ge=0, le=MAX_CORRELATION_GRAPH_EDGES)]
    limits_reached: bool


class MultilayerCorrelationRequest(StrictContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    batch: EvidenceBatch


class MultilayerCorrelationResult(StrictContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    batch_id: Annotated[str, Field(pattern=r"^evb_[0-9a-f]{64}$")]
    rules_version: Literal["correlation-rules/1.0.0"] = "correlation-rules/1.0.0"
    identity_rules_version: Literal["identity-rules/1.0.0"] = "identity-rules/1.0.0"
    candidates: Annotated[
        tuple[CorrelationCandidate, ...], Field(max_length=MAX_CORRELATION_CANDIDATES)
    ]
    evaluations: Annotated[
        tuple[CorrelationEvaluation, ...], Field(max_length=MAX_CORRELATION_EVALUATIONS)
    ]
    relationships: Annotated[
        tuple[CorrelationRelationship, ...],
        Field(max_length=MAX_CORRELATION_RELATIONSHIPS),
    ]
    conflicts: Annotated[
        tuple[CorrelationConflict, ...], Field(max_length=MAX_CORRELATION_CONFLICTS)
    ]
    graph_nodes: Annotated[tuple[CorrelationGraphNode, ...], Field(max_length=256)]
    graph_edges: Annotated[
        tuple[CorrelationGraphEdge, ...], Field(max_length=MAX_CORRELATION_GRAPH_EDGES)
    ]
    summary: CorrelationSummary
    limitations: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...],
        Field(min_length=1, max_length=16),
    ]
    persistence_performed: Literal[False] = False
    causal_inference_performed: Literal[False] = False
    temporal_sequence_inferred: Literal[False] = False
    threat_verdict_generated: Literal[False] = False
    risk_score_generated: Literal[False] = False
    attack_finding_generated: Literal[False] = False
    exploitation_inferred: Literal[False] = False
    ml_promoted_to_observation: Literal[False] = False
    trust_promoted: Literal[False] = False

    @model_validator(mode="after")
    def enforce_result_invariants(self) -> Self:
        ordered = (
            (self.candidates, "candidate_id"),
            (self.evaluations, "evaluation_id"),
            (self.relationships, "relationship_id"),
            (self.conflicts, "conflict_id"),
            (self.graph_nodes, "node_id"),
            (self.graph_edges, "edge_id"),
        )
        for values, field in ordered:
            identifiers = tuple(getattr(item, field) for item in values)
            if identifiers != tuple(sorted(identifiers)):
                raise ValueError(f"{field} values must be deterministically ordered")
        counts = {status: 0 for status in CorrelationStatus}
        for evaluation in self.evaluations:
            counts[evaluation.status] += 1
        expected = self.summary.model_copy(
            update={
                "candidates": len(self.candidates),
                "evaluations": len(self.evaluations),
                "supported": counts[CorrelationStatus.SUPPORTED],
                "insufficient_evidence": counts[
                    CorrelationStatus.INSUFFICIENT_EVIDENCE
                ],
                "conflicting_evidence": counts[CorrelationStatus.CONFLICTING_EVIDENCE],
                "not_applicable": counts[CorrelationStatus.NOT_APPLICABLE],
                "unsupported_relation": counts[CorrelationStatus.UNSUPPORTED_RELATION],
                "relationships": len(self.relationships),
                "conflicts": len(self.conflicts),
                "graph_nodes": len(self.graph_nodes),
                "graph_edges": len(self.graph_edges),
            }
        )
        if self.summary != expected:
            raise ValueError("correlation summary is inconsistent")
        relationship_ids = {item.relationship_id for item in self.relationships}
        if any(
            item.relationship_id not in relationship_ids for item in self.graph_edges
        ):
            raise ValueError("graph edges must reference published relationships")
        encoded = json.dumps(
            self.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode()
        if len(encoded) > MAX_CORRELATION_OUTPUT_BYTES:
            raise ValueError("correlation output exceeds the size limit")
        return self
