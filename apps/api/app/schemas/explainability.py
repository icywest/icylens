from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Annotated, Literal, Self, TypeAlias

from pydantic import Field, model_validator

from app.schemas.correlation import (
    CorrelationRelationshipType,
    CorrelationStatus,
)
from app.schemas.evidence import (
    EvidenceBatch,
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
from app.schemas.sufficiency import (
    AssertionSelection,
    ContradictionCategory,
    RequirementState,
    SufficiencyState,
    UncertaintyCategory,
)
from app.schemas.vulnerability import StrictContract

EXPLAINABILITY_SCHEMA_VERSION = "1.0.0"
MAX_TRACES_PER_REQUEST = 32
MAX_TRACE_NODES = 128
MAX_TRACE_EDGES = 256
MAX_TRACE_DEPTH = 8
MAX_EXPLANATION_STATEMENTS = 64
MAX_TRACE_EVIDENCE_REFERENCES = 16
MAX_TRACE_IDENTITY_REFERENCES = 16
MAX_TRACE_CORRELATION_REFERENCES = 16
MAX_TRACE_REQUIREMENTS = 8
MAX_TRACE_CONTRADICTIONS = 16
MAX_TRACE_UNCERTAINTIES = 32
MAX_TRACE_LIMITATIONS = 16
MAX_EXPLAINABILITY_OUTPUT_BYTES = 1024 * 1024

TraceId: TypeAlias = Annotated[str, Field(pattern=r"^dtr_[0-9a-f]{64}$", max_length=68)]
TraceNodeId: TypeAlias = Annotated[
    str, Field(pattern=r"^trn_[0-9a-f]{64}$", max_length=68)
]
TraceEdgeId: TypeAlias = Annotated[
    str, Field(pattern=r"^tre_[0-9a-f]{64}$", max_length=68)
]
ExplanationStatementId: TypeAlias = Annotated[
    str, Field(pattern=r"^tst_[0-9a-f]{64}$", max_length=68)
]
TraceLimitationId: TypeAlias = Annotated[
    str, Field(pattern=r"^tli_[0-9a-f]{64}$", max_length=68)
]


def trace_content_id(prefix: str, value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return f"{prefix}_{hashlib.sha256(encoded).hexdigest()}"


class TraceNodeType(str, Enum):
    EVIDENCE = "evidence"
    IDENTITY_RESOLUTION = "identity_resolution"
    CORRELATION_RELATION = "correlation_relation"
    ASSERTION = "assertion"
    POLICY = "policy"
    REQUIREMENT = "requirement"
    CONTRADICTION = "contradiction"
    UNCERTAINTY = "uncertainty"
    LIMITATION = "limitation"


class TraceNodeState(str, Enum):
    PRESENT = "present"
    APPLICABLE = "applicable"
    RETAINED = "retained"
    SUPPORTED = "supported"
    SAME_IDENTITY = "same_identity"
    SUFFICIENT = "sufficient"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    CONFLICTING_EVIDENCE = "conflicting_evidence"
    NOT_APPLICABLE = "not_applicable"
    UNSUPPORTED_ASSERTION = "unsupported_assertion"
    SATISFIED = "satisfied"
    MISSING = "missing"
    CONFLICTING = "conflicting"


class TraceEdgeType(str, Enum):
    USES_EVIDENCE = "uses_evidence"
    EVALUATED_BY = "evaluated_by"
    DEPENDS_ON_IDENTITY = "depends_on_identity"
    DEPENDS_ON_CORRELATION = "depends_on_correlation"
    SATISFIES_REQUIREMENT = "satisfies_requirement"
    MISSING_REQUIREMENT = "missing_requirement"
    CONFLICTS_WITH = "conflicts_with"
    QUALIFIED_BY = "qualified_by"
    LIMITED_BY = "limited_by"


class IdentityReferenceKind(str, Enum):
    GROUP = "group"
    MATCH = "match"


class CorrelationReferenceKind(str, Enum):
    RELATIONSHIP = "relationship"
    EVALUATION = "evaluation"


class ExplanationTemplateId(str, Enum):
    DECISION_SUFFICIENT = "decision_sufficient"
    DECISION_INSUFFICIENT = "decision_insufficient"
    DECISION_CONFLICTING = "decision_conflicting"
    DECISION_NOT_APPLICABLE = "decision_not_applicable"
    DECISION_UNSUPPORTED = "decision_unsupported"
    REQUIREMENT_SATISFIED = "requirement_satisfied"
    REQUIREMENT_MISSING = "requirement_missing"
    REQUIREMENT_CONFLICTING = "requirement_conflicting"
    REQUIREMENT_NOT_APPLICABLE = "requirement_not_applicable"
    CONTRADICTION_RETAINED = "contradiction_retained"
    UNCERTAINTY_RETAINED = "uncertainty_retained"
    LIMITATION_RETAINED = "limitation_retained"


EXPLANATION_MESSAGES = {
    ExplanationTemplateId.DECISION_SUFFICIENT: "All requirements for the registered assertion are satisfied; the conclusion remains limited to that statement.",
    ExplanationTemplateId.DECISION_INSUFFICIENT: "Required evidence is missing; the absence does not prove the assertion false.",
    ExplanationTemplateId.DECISION_CONFLICTING: "Relevant retained evidence conflicts; no source is selected as authoritative.",
    ExplanationTemplateId.DECISION_NOT_APPLICABLE: "The registered policy does not apply to the selected evidence domains.",
    ExplanationTemplateId.DECISION_UNSUPPORTED: "No registered policy can evaluate this assertion; no heuristic alternative is generated.",
    ExplanationTemplateId.REQUIREMENT_SATISFIED: "This requirement is satisfied by the referenced backend evidence or dependency.",
    ExplanationTemplateId.REQUIREMENT_MISSING: "This requirement is missing and remains visible in the decision trace.",
    ExplanationTemplateId.REQUIREMENT_CONFLICTING: "This requirement is affected by a relevant retained contradiction.",
    ExplanationTemplateId.REQUIREMENT_NOT_APPLICABLE: "This requirement is not applicable under the selected evidence domains.",
    ExplanationTemplateId.CONTRADICTION_RETAINED: "A relevant contradiction is preserved without source precedence or suppression.",
    ExplanationTemplateId.UNCERTAINTY_RETAINED: "A categorical uncertainty remains; it is not converted into a numerical confidence score.",
    ExplanationTemplateId.LIMITATION_RETAINED: "A registered scientific limitation constrains interpretation beyond the assessed statement.",
}


class TraceIdentifier(StrictContract):
    trace_id: TraceId
    source_assessment_id: Annotated[str, Field(pattern=r"^sas_[0-9a-f]{64}$")]
    algorithm: Literal["sha256-canonical-json-v1"] = "sha256-canonical-json-v1"
    deterministic: Literal[True] = True


class TraceNode(StrictContract):
    node_id: TraceNodeId
    node_type: TraceNodeType
    object_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{2,127}$")]
    state: TraceNodeState

    @model_validator(mode="after")
    def verify_identifier(self) -> Self:
        material = {
            "node_type": self.node_type.value,
            "object_id": self.object_id,
            "state": self.state.value,
        }
        if self.node_id != trace_content_id("trn", material):
            raise ValueError("trace node ID does not match canonical content")
        return self


class TraceEdge(StrictContract):
    edge_id: TraceEdgeId
    edge_type: TraceEdgeType
    source_node_id: TraceNodeId
    target_node_id: TraceNodeId
    direct_dependency: Literal[True] = True
    transitive_inference: Literal[False] = False

    @model_validator(mode="after")
    def verify_identifier(self) -> Self:
        if self.source_node_id == self.target_node_id:
            raise ValueError("trace edge cannot be a self-loop")
        material = {
            "edge_type": self.edge_type.value,
            "source": self.source_node_id,
            "target": self.target_node_id,
        }
        if self.edge_id != trace_content_id("tre", material):
            raise ValueError("trace edge ID does not match canonical content")
        return self


class TraceEvidenceReference(StrictContract):
    evidence_id: EvidenceId
    source_module: EvidenceSourceModule
    source_phase: Literal["02", "03", "04", "05"]
    origin_type: EvidenceOriginType
    trust_classification: EvidenceTrustClassification
    synthetic: bool
    origin_verified: bool
    verification_status: EvidenceVerificationStatus
    raw_content_disclosed: Literal[False] = False


class TracePolicyReference(StrictContract):
    assertion_id: Annotated[str, Field(pattern=r"^AS-[A-Z]+-[0-9]{3}$")]
    policy_version: Literal["1.0.0"] = "1.0.0"
    registry_version: Literal["sufficiency-assertions/1.0.0"] = (
        "sufficiency-assertions/1.0.0"
    )
    executable_policy: Literal[False] = False


class TraceIdentityReference(StrictContract):
    reference_kind: IdentityReferenceKind
    identity_object_id: Annotated[str, Field(pattern=r"^(?:idg|idm)_[0-9a-f]{64}$")]
    rule_id: Annotated[str, Field(pattern=r"^IR-[A-Z]+-[0-9]{3}$")]
    rule_version: Literal["1.0.0"] = "1.0.0"
    status: IdentityResolutionStatus
    identity_type: IdentityType | None
    namespace: IdentityNamespace | None
    evidence_ids: Annotated[tuple[EvidenceId, ...], Field(min_length=1, max_length=256)]


class TraceCorrelationReference(StrictContract):
    reference_kind: CorrelationReferenceKind
    correlation_object_id: Annotated[str, Field(pattern=r"^(?:crr|cre)_[0-9a-f]{64}$")]
    rule_id: Annotated[str, Field(pattern=r"^CR-[A-Z]+-[0-9]{3}$")]
    rule_version: Literal["1.0.0"] = "1.0.0"
    status: CorrelationStatus
    relationship_type: CorrelationRelationshipType | None
    evidence_ids: Annotated[tuple[EvidenceId, ...], Field(min_length=1, max_length=256)]


class TraceRequirementReference(StrictContract):
    requirement_evaluation_id: Annotated[str, Field(pattern=r"^sre_[0-9a-f]{64}$")]
    requirement_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")]
    state: RequirementState
    evidence_ids: Annotated[tuple[EvidenceId, ...], Field(max_length=16)]
    relationship_ids: Annotated[
        tuple[Annotated[str, Field(pattern=r"^crr_[0-9a-f]{64}$")], ...],
        Field(max_length=4),
    ]


class TraceContradictionReference(StrictContract):
    contradiction_id: Annotated[str, Field(pattern=r"^sct_[0-9a-f]{64}$")]
    category: ContradictionCategory
    requirement_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")]
    evidence_ids: Annotated[tuple[EvidenceId, ...], Field(min_length=1, max_length=256)]
    source_conflict_id: Annotated[str, Field(pattern=r"^(?:idf|crf)_[0-9a-f]{64}$")]
    source_precedence_applied: Literal[False] = False


class TraceUncertaintyReference(StrictContract):
    uncertainty_id: Annotated[str, Field(pattern=r"^sur_[0-9a-f]{64}$")]
    category: UncertaintyCategory
    evidence_ids: Annotated[tuple[EvidenceId, ...], Field(max_length=16)]
    affects_sufficiency: bool
    numeric_confidence: Literal[None] = None


class TraceLimitation(StrictContract):
    limitation_id: TraceLimitationId
    limitation_code: Annotated[str, Field(pattern=r"^limitation_[0-9]{3}$")]
    statement: Annotated[str, Field(min_length=1, max_length=512)]
    registered_statement: Literal[True] = True

    @model_validator(mode="after")
    def verify_identifier(self) -> Self:
        material = {
            "limitation_code": self.limitation_code,
            "statement": self.statement,
        }
        if self.limitation_id != trace_content_id("tli", material):
            raise ValueError("trace limitation ID does not match canonical content")
        return self


class ExplanationStatement(StrictContract):
    statement_id: ExplanationStatementId
    template_id: ExplanationTemplateId
    template_version: Literal["1.0.0"] = "1.0.0"
    source_reference_id: Annotated[
        str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{2,127}$")
    ]
    message: Annotated[str, Field(min_length=1, max_length=512)]
    generated_by_llm: Literal[False] = False

    @model_validator(mode="after")
    def verify_statement(self) -> Self:
        if self.message != EXPLANATION_MESSAGES[self.template_id]:
            raise ValueError("explanation message must match its static template")
        material = {
            "template_id": self.template_id.value,
            "template_version": self.template_version,
            "source_reference_id": self.source_reference_id,
        }
        if self.statement_id != trace_content_id("tst", material):
            raise ValueError(
                "explanation statement ID does not match canonical content"
            )
        return self


class ExplanationSummary(StrictContract):
    decision_status: SufficiencyState
    evidence_references: Annotated[int, Field(ge=0, le=16)]
    identity_references: Annotated[int, Field(ge=0, le=16)]
    correlation_references: Annotated[int, Field(ge=0, le=16)]
    requirements: Annotated[int, Field(ge=0, le=8)]
    satisfied_requirements: Annotated[int, Field(ge=0, le=8)]
    missing_requirements: Annotated[int, Field(ge=0, le=8)]
    conflicting_requirements: Annotated[int, Field(ge=0, le=8)]
    not_applicable_requirements: Annotated[int, Field(ge=0, le=8)]
    contradictions: Annotated[int, Field(ge=0, le=16)]
    uncertainties: Annotated[int, Field(ge=0, le=32)]
    limitations: Annotated[int, Field(ge=0, le=16)]
    nodes: Annotated[int, Field(ge=1, le=MAX_TRACE_NODES)]
    edges: Annotated[int, Field(ge=0, le=MAX_TRACE_EDGES)]
    maximum_depth: Annotated[int, Field(ge=0, le=MAX_TRACE_DEPTH)]
    requirements_complete: bool


class DecisionTrace(StrictContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    identifier: TraceIdentifier
    assertion_id: Annotated[str, Field(pattern=r"^AS-[A-Z]+-[0-9]{3}$")]
    decision_status: SufficiencyState
    policy_reference: TracePolicyReference | None
    evidence_references: Annotated[
        tuple[TraceEvidenceReference, ...],
        Field(max_length=MAX_TRACE_EVIDENCE_REFERENCES),
    ]
    identity_references: Annotated[
        tuple[TraceIdentityReference, ...],
        Field(max_length=MAX_TRACE_IDENTITY_REFERENCES),
    ]
    correlation_references: Annotated[
        tuple[TraceCorrelationReference, ...],
        Field(max_length=MAX_TRACE_CORRELATION_REFERENCES),
    ]
    requirement_references: Annotated[
        tuple[TraceRequirementReference, ...], Field(max_length=MAX_TRACE_REQUIREMENTS)
    ]
    contradiction_references: Annotated[
        tuple[TraceContradictionReference, ...],
        Field(max_length=MAX_TRACE_CONTRADICTIONS),
    ]
    uncertainty_references: Annotated[
        tuple[TraceUncertaintyReference, ...],
        Field(max_length=MAX_TRACE_UNCERTAINTIES),
    ]
    limitations: Annotated[
        tuple[TraceLimitation, ...], Field(max_length=MAX_TRACE_LIMITATIONS)
    ]
    nodes: Annotated[
        tuple[TraceNode, ...], Field(min_length=1, max_length=MAX_TRACE_NODES)
    ]
    edges: Annotated[tuple[TraceEdge, ...], Field(max_length=MAX_TRACE_EDGES)]
    explanation_statements: Annotated[
        tuple[ExplanationStatement, ...], Field(max_length=MAX_EXPLANATION_STATEMENTS)
    ]
    summary: ExplanationSummary
    causal_explanation: Literal[False] = False
    threat_confirmed: Literal[False] = False
    decision_changed: Literal[False] = False

    @model_validator(mode="after")
    def enforce_integrity(self) -> Self:
        node_ids = tuple(item.node_id for item in self.nodes)
        node_object_ids = tuple(item.object_id for item in self.nodes)
        edge_ids = tuple(item.edge_id for item in self.edges)
        statement_ids = tuple(item.statement_id for item in self.explanation_statements)
        for identifiers, label in (
            (node_ids, "nodes"),
            (edge_ids, "edges"),
            (statement_ids, "statements"),
        ):
            if identifiers != tuple(sorted(identifiers)):
                raise ValueError(f"trace {label} must be deterministically ordered")
            if len(identifiers) != len(set(identifiers)):
                raise ValueError(f"trace {label} must be unique")
        if len(node_object_ids) != len(set(node_object_ids)):
            raise ValueError("trace node objects must be unique")
        known_nodes = set(node_ids)
        if any(
            edge.source_node_id not in known_nodes
            or edge.target_node_id not in known_nodes
            for edge in self.edges
        ):
            raise ValueError("trace edges must reference existing nodes")
        adjacency: dict[str, list[str]] = {item: [] for item in node_ids}
        for edge in self.edges:
            adjacency[edge.source_node_id].append(edge.target_node_id)
        visiting: set[str] = set()
        depth_by_node: dict[str, int] = {}

        def visit(node: str) -> int:
            if node in visiting:
                raise ValueError("decision trace dependencies must be acyclic")
            if node in depth_by_node:
                return depth_by_node[node]
            visiting.add(node)
            depth = 0
            for target in adjacency[node]:
                depth = max(depth, 1 + visit(target))
            visiting.remove(node)
            depth_by_node[node] = depth
            return depth

        maximum_depth = max((visit(node) for node in node_ids), default=0)
        if maximum_depth > MAX_TRACE_DEPTH:
            raise ValueError("decision trace exceeds maximum dependency depth")
        object_ids = set(node_object_ids)
        reference_groups = (
            tuple(item.evidence_id for item in self.evidence_references),
            tuple(item.identity_object_id for item in self.identity_references),
            tuple(item.correlation_object_id for item in self.correlation_references),
            tuple(
                item.requirement_evaluation_id for item in self.requirement_references
            ),
            tuple(item.contradiction_id for item in self.contradiction_references),
            tuple(item.uncertainty_id for item in self.uncertainty_references),
            tuple(item.limitation_id for item in self.limitations),
        )
        if any(len(items) != len(set(items)) for items in reference_groups):
            raise ValueError("trace references must be unique")
        referenced_objects = {
            *(item.evidence_id for item in self.evidence_references),
            *(item.identity_object_id for item in self.identity_references),
            *(item.correlation_object_id for item in self.correlation_references),
            *(item.requirement_evaluation_id for item in self.requirement_references),
            *(item.contradiction_id for item in self.contradiction_references),
            *(item.uncertainty_id for item in self.uncertainty_references),
            *(item.limitation_id for item in self.limitations),
        }
        expected_node_objects = referenced_objects | {
            self.identifier.source_assessment_id
        }
        if self.decision_status is SufficiencyState.UNSUPPORTED_ASSERTION:
            if self.policy_reference is not None:
                raise ValueError("unsupported assertion cannot reference a policy")
        elif self.policy_reference is None:
            raise ValueError("supported policy state requires a policy reference")
        if self.policy_reference is not None:
            if self.policy_reference.assertion_id != self.assertion_id:
                raise ValueError("trace policy must match the assessed assertion")
            expected_node_objects.add(
                f"{self.policy_reference.assertion_id}@{self.policy_reference.policy_version}"
            )
        if object_ids != expected_node_objects:
            raise ValueError("trace nodes must correspond exactly to trace references")
        node_by_object = {item.object_id: item for item in self.nodes}
        expected_nodes: dict[str, tuple[TraceNodeType, TraceNodeState]] = {
            self.identifier.source_assessment_id: (
                TraceNodeType.ASSERTION,
                TraceNodeState(self.decision_status.value),
            ),
            **{
                item.evidence_id: (TraceNodeType.EVIDENCE, TraceNodeState.PRESENT)
                for item in self.evidence_references
            },
            **{
                item.requirement_evaluation_id: (
                    TraceNodeType.REQUIREMENT,
                    TraceNodeState(item.state.value),
                )
                for item in self.requirement_references
            },
            **{
                item.contradiction_id: (
                    TraceNodeType.CONTRADICTION,
                    TraceNodeState.CONFLICTING,
                )
                for item in self.contradiction_references
            },
            **{
                item.uncertainty_id: (
                    TraceNodeType.UNCERTAINTY,
                    TraceNodeState.RETAINED,
                )
                for item in self.uncertainty_references
            },
            **{
                item.limitation_id: (
                    TraceNodeType.LIMITATION,
                    TraceNodeState.RETAINED,
                )
                for item in self.limitations
            },
        }
        for identity_reference in self.identity_references:
            state = {
                IdentityResolutionStatus.SAME_IDENTITY: TraceNodeState.SAME_IDENTITY,
                IdentityResolutionStatus.CONFLICTING_IDENTITY: TraceNodeState.CONFLICTING,
            }.get(identity_reference.status, TraceNodeState.MISSING)
            expected_nodes[identity_reference.identity_object_id] = (
                TraceNodeType.IDENTITY_RESOLUTION,
                state,
            )
        for correlation_reference in self.correlation_references:
            state = {
                CorrelationStatus.SUPPORTED: TraceNodeState.SUPPORTED,
                CorrelationStatus.CONFLICTING_EVIDENCE: TraceNodeState.CONFLICTING,
                CorrelationStatus.NOT_APPLICABLE: TraceNodeState.NOT_APPLICABLE,
            }.get(correlation_reference.status, TraceNodeState.MISSING)
            expected_nodes[correlation_reference.correlation_object_id] = (
                TraceNodeType.CORRELATION_RELATION,
                state,
            )
        if self.policy_reference is not None:
            expected_nodes[
                f"{self.policy_reference.assertion_id}@{self.policy_reference.policy_version}"
            ] = (TraceNodeType.POLICY, TraceNodeState.APPLICABLE)
        if any(
            (node_by_object[object_id].node_type, node_by_object[object_id].state)
            != expected
            for object_id, expected in expected_nodes.items()
        ):
            raise ValueError("trace node semantics are inconsistent")
        decision_templates = {
            SufficiencyState.SUFFICIENT: ExplanationTemplateId.DECISION_SUFFICIENT,
            SufficiencyState.INSUFFICIENT_EVIDENCE: ExplanationTemplateId.DECISION_INSUFFICIENT,
            SufficiencyState.CONFLICTING_EVIDENCE: ExplanationTemplateId.DECISION_CONFLICTING,
            SufficiencyState.NOT_APPLICABLE: ExplanationTemplateId.DECISION_NOT_APPLICABLE,
            SufficiencyState.UNSUPPORTED_ASSERTION: ExplanationTemplateId.DECISION_UNSUPPORTED,
        }
        requirement_templates = {
            RequirementState.SATISFIED: ExplanationTemplateId.REQUIREMENT_SATISFIED,
            RequirementState.MISSING: ExplanationTemplateId.REQUIREMENT_MISSING,
            RequirementState.CONFLICTING: ExplanationTemplateId.REQUIREMENT_CONFLICTING,
            RequirementState.NOT_APPLICABLE: ExplanationTemplateId.REQUIREMENT_NOT_APPLICABLE,
        }
        expected_explanations = {
            (
                self.identifier.source_assessment_id,
                decision_templates[self.decision_status],
            ),
            *(
                (item.requirement_evaluation_id, requirement_templates[item.state])
                for item in self.requirement_references
            ),
            *(
                (item.contradiction_id, ExplanationTemplateId.CONTRADICTION_RETAINED)
                for item in self.contradiction_references
            ),
            *(
                (item.uncertainty_id, ExplanationTemplateId.UNCERTAINTY_RETAINED)
                for item in self.uncertainty_references
            ),
            *(
                (item.limitation_id, ExplanationTemplateId.LIMITATION_RETAINED)
                for item in self.limitations
            ),
        }
        actual_explanations = {
            (item.source_reference_id, item.template_id)
            for item in self.explanation_statements
        }
        if actual_explanations != expected_explanations or len(
            actual_explanations
        ) != len(self.explanation_statements):
            raise ValueError("trace explanation is incomplete or inconsistent")
        states = {state: 0 for state in RequirementState}
        for requirement in self.requirement_references:
            states[requirement.state] += 1
        expected_summary = self.summary.model_copy(
            update={
                "decision_status": self.decision_status,
                "evidence_references": len(self.evidence_references),
                "identity_references": len(self.identity_references),
                "correlation_references": len(self.correlation_references),
                "requirements": len(self.requirement_references),
                "satisfied_requirements": states[RequirementState.SATISFIED],
                "missing_requirements": states[RequirementState.MISSING],
                "conflicting_requirements": states[RequirementState.CONFLICTING],
                "not_applicable_requirements": states[RequirementState.NOT_APPLICABLE],
                "contradictions": len(self.contradiction_references),
                "uncertainties": len(self.uncertainty_references),
                "limitations": len(self.limitations),
                "nodes": len(self.nodes),
                "edges": len(self.edges),
                "maximum_depth": maximum_depth,
                "requirements_complete": len(self.requirement_references)
                == len(
                    {
                        item.requirement_evaluation_id
                        for item in self.requirement_references
                    }
                ),
            }
        )
        if self.summary != expected_summary:
            raise ValueError("explanation summary is inconsistent")
        material = {
            "source_assessment_id": self.identifier.source_assessment_id,
            "assertion_id": self.assertion_id,
            "decision_status": self.decision_status.value,
            "policy": None
            if self.policy_reference is None
            else (
                self.policy_reference.assertion_id,
                self.policy_reference.policy_version,
                self.policy_reference.registry_version,
            ),
            "nodes": node_ids,
            "edges": edge_ids,
            "statements": statement_ids,
        }
        if self.identifier.trace_id != trace_content_id("dtr", material):
            raise ValueError("decision trace ID does not match canonical content")
        return self


class DecisionTraceRequest(StrictContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    batch: EvidenceBatch
    assertions: Annotated[
        tuple[AssertionSelection, ...],
        Field(min_length=1, max_length=MAX_TRACES_PER_REQUEST),
    ]

    @model_validator(mode="after")
    def reject_duplicate_selections(self) -> Self:
        keys = tuple((item.assertion_id, item.evidence_ids) for item in self.assertions)
        if len(keys) != len(set(keys)):
            raise ValueError("trace assertion selections must be unique")
        return self


class DecisionTraceResult(StrictContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    batch_id: Annotated[str, Field(pattern=r"^evb_[0-9a-f]{64}$")]
    trace_version: Literal["decision-trace/1.0.0"] = "decision-trace/1.0.0"
    identity_rules_version: Literal["identity-rules/1.0.0"] = "identity-rules/1.0.0"
    correlation_rules_version: Literal["correlation-rules/1.0.0"] = (
        "correlation-rules/1.0.0"
    )
    sufficiency_policy_version: Literal["sufficiency-assertions/1.0.0"] = (
        "sufficiency-assertions/1.0.0"
    )
    traces: Annotated[
        tuple[DecisionTrace, ...], Field(max_length=MAX_TRACES_PER_REQUEST)
    ]
    limitations: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...],
        Field(min_length=1, max_length=16),
    ]
    persistence_performed: Literal[False] = False
    causal_inference_performed: Literal[False] = False
    threat_verdict_generated: Literal[False] = False
    scoring_performed: Literal[False] = False
    response_action_performed: Literal[False] = False

    @model_validator(mode="after")
    def enforce_result(self) -> Self:
        trace_ids = tuple(item.identifier.trace_id for item in self.traces)
        if trace_ids != tuple(sorted(trace_ids)):
            raise ValueError("decision traces must be deterministically ordered")
        encoded = json.dumps(
            self.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode()
        if len(encoded) > MAX_EXPLAINABILITY_OUTPUT_BYTES:
            raise ValueError("decision trace output exceeds the size limit")
        return self
