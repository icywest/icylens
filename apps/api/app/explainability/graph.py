from __future__ import annotations

from app.explainability.templates import (
    decision_statement,
    explanation_statement,
    requirement_statement,
)
from app.schemas.explainability import (
    DecisionTrace,
    ExplanationStatement,
    ExplanationSummary,
    ExplanationTemplateId,
    TraceContradictionReference,
    TraceCorrelationReference,
    TraceEdge,
    TraceEdgeType,
    TraceEvidenceReference,
    TraceIdentifier,
    TraceIdentityReference,
    TraceLimitation,
    TraceNode,
    TraceNodeState,
    TraceNodeType,
    TracePolicyReference,
    TraceRequirementReference,
    TraceUncertaintyReference,
    trace_content_id,
)
from app.schemas.identity import IdentityResolutionStatus
from app.schemas.sufficiency import RequirementState, SufficiencyAssessment


def _node(node_type: TraceNodeType, object_id: str, state: TraceNodeState) -> TraceNode:
    material = {
        "node_type": node_type.value,
        "object_id": object_id,
        "state": state.value,
    }
    return TraceNode(
        node_id=trace_content_id("trn", material),
        node_type=node_type,
        object_id=object_id,
        state=state,
    )


def _edge(edge_type: TraceEdgeType, source: TraceNode, target: TraceNode) -> TraceEdge:
    material = {
        "edge_type": edge_type.value,
        "source": source.node_id,
        "target": target.node_id,
    }
    return TraceEdge(
        edge_id=trace_content_id("tre", material),
        edge_type=edge_type,
        source_node_id=source.node_id,
        target_node_id=target.node_id,
    )


def _identity_state(reference: TraceIdentityReference) -> TraceNodeState:
    if reference.status is IdentityResolutionStatus.SAME_IDENTITY:
        return TraceNodeState.SAME_IDENTITY
    if reference.status is IdentityResolutionStatus.CONFLICTING_IDENTITY:
        return TraceNodeState.CONFLICTING
    return TraceNodeState.MISSING


def _correlation_state(reference: TraceCorrelationReference) -> TraceNodeState:
    if reference.status.value == "supported":
        return TraceNodeState.SUPPORTED
    if reference.status.value == "conflicting_evidence":
        return TraceNodeState.CONFLICTING
    if reference.status.value == "not_applicable":
        return TraceNodeState.NOT_APPLICABLE
    return TraceNodeState.MISSING


def _maximum_depth(nodes: tuple[TraceNode, ...], edges: tuple[TraceEdge, ...]) -> int:
    adjacency: dict[str, list[str]] = {item.node_id: [] for item in nodes}
    for edge in edges:
        adjacency[edge.source_node_id].append(edge.target_node_id)

    def depth(node_id: str) -> int:
        return max((1 + depth(item) for item in adjacency[node_id]), default=0)

    return max((depth(item.node_id) for item in nodes), default=0)


def build_decision_trace(
    assessment: SufficiencyAssessment,
    policy_reference: TracePolicyReference | None,
    evidence_references: tuple[TraceEvidenceReference, ...],
    identity_references: tuple[TraceIdentityReference, ...],
    correlation_references: tuple[TraceCorrelationReference, ...],
    requirement_references: tuple[TraceRequirementReference, ...],
    contradiction_references: tuple[TraceContradictionReference, ...],
    uncertainty_references: tuple[TraceUncertaintyReference, ...],
    limitations: tuple[TraceLimitation, ...],
) -> DecisionTrace:
    nodes: dict[str, TraceNode] = {}
    edges: dict[str, TraceEdge] = {}

    def add_node(node: TraceNode) -> TraceNode:
        nodes[node.object_id] = node
        return node

    def add_edge(edge: TraceEdge) -> None:
        edges[edge.edge_id] = edge

    root = add_node(
        _node(
            TraceNodeType.ASSERTION,
            assessment.assessment_id,
            TraceNodeState(assessment.state.value),
        )
    )
    if policy_reference is not None:
        policy_node = add_node(
            _node(
                TraceNodeType.POLICY,
                f"{policy_reference.assertion_id}@{policy_reference.policy_version}",
                TraceNodeState.APPLICABLE,
            )
        )
        add_edge(_edge(TraceEdgeType.EVALUATED_BY, root, policy_node))
    for evidence_reference in evidence_references:
        node = add_node(
            _node(
                TraceNodeType.EVIDENCE,
                evidence_reference.evidence_id,
                TraceNodeState.PRESENT,
            )
        )
        add_edge(_edge(TraceEdgeType.USES_EVIDENCE, root, node))
    requirement_nodes: dict[str, TraceNode] = {}
    for requirement_reference in requirement_references:
        node = add_node(
            _node(
                TraceNodeType.REQUIREMENT,
                requirement_reference.requirement_evaluation_id,
                TraceNodeState(requirement_reference.state.value),
            )
        )
        requirement_nodes[requirement_reference.requirement_id] = node
        edge_type = {
            RequirementState.SATISFIED: TraceEdgeType.SATISFIES_REQUIREMENT,
            RequirementState.MISSING: TraceEdgeType.MISSING_REQUIREMENT,
            RequirementState.CONFLICTING: TraceEdgeType.CONFLICTS_WITH,
            RequirementState.NOT_APPLICABLE: TraceEdgeType.MISSING_REQUIREMENT,
        }[requirement_reference.state]
        add_edge(_edge(edge_type, root, node))
    identity_requirement = requirement_nodes.get("required_identity_satisfied")
    for identity_reference in identity_references:
        node = add_node(
            _node(
                TraceNodeType.IDENTITY_RESOLUTION,
                identity_reference.identity_object_id,
                _identity_state(identity_reference),
            )
        )
        add_edge(
            _edge(
                TraceEdgeType.DEPENDS_ON_IDENTITY,
                root if identity_requirement is None else identity_requirement,
                node,
            )
        )
    correlation_requirement = requirement_nodes.get("required_correlation_supported")
    for correlation_reference in correlation_references:
        node = add_node(
            _node(
                TraceNodeType.CORRELATION_RELATION,
                correlation_reference.correlation_object_id,
                _correlation_state(correlation_reference),
            )
        )
        add_edge(
            _edge(
                TraceEdgeType.DEPENDS_ON_CORRELATION,
                root if correlation_requirement is None else correlation_requirement,
                node,
            )
        )
    for contradiction_reference in contradiction_references:
        node = add_node(
            _node(
                TraceNodeType.CONTRADICTION,
                contradiction_reference.contradiction_id,
                TraceNodeState.CONFLICTING,
            )
        )
        source = requirement_nodes.get(contradiction_reference.requirement_id, root)
        add_edge(_edge(TraceEdgeType.CONFLICTS_WITH, source, node))
    for uncertainty_reference in uncertainty_references:
        node = add_node(
            _node(
                TraceNodeType.UNCERTAINTY,
                uncertainty_reference.uncertainty_id,
                TraceNodeState.RETAINED,
            )
        )
        add_edge(_edge(TraceEdgeType.QUALIFIED_BY, root, node))
    for limitation in limitations:
        node = add_node(
            _node(
                TraceNodeType.LIMITATION,
                limitation.limitation_id,
                TraceNodeState.RETAINED,
            )
        )
        add_edge(_edge(TraceEdgeType.LIMITED_BY, root, node))

    statements: list[ExplanationStatement] = [
        decision_statement(assessment.state, assessment.assessment_id)
    ]
    statements.extend(
        requirement_statement(item.state, item.requirement_evaluation_id)
        for item in requirement_references
    )
    statements.extend(
        explanation_statement(
            ExplanationTemplateId.CONTRADICTION_RETAINED, item.contradiction_id
        )
        for item in contradiction_references
    )
    statements.extend(
        explanation_statement(
            ExplanationTemplateId.UNCERTAINTY_RETAINED, item.uncertainty_id
        )
        for item in uncertainty_references
    )
    statements.extend(
        explanation_statement(
            ExplanationTemplateId.LIMITATION_RETAINED, item.limitation_id
        )
        for item in limitations
    )
    ordered_nodes = tuple(sorted(nodes.values(), key=lambda item: item.node_id))
    ordered_edges = tuple(sorted(edges.values(), key=lambda item: item.edge_id))
    ordered_statements = tuple(sorted(statements, key=lambda item: item.statement_id))
    requirement_counts = {state: 0 for state in RequirementState}
    for requirement_reference in requirement_references:
        requirement_counts[requirement_reference.state] += 1
    summary = ExplanationSummary(
        decision_status=assessment.state,
        evidence_references=len(evidence_references),
        identity_references=len(identity_references),
        correlation_references=len(correlation_references),
        requirements=len(requirement_references),
        satisfied_requirements=requirement_counts[RequirementState.SATISFIED],
        missing_requirements=requirement_counts[RequirementState.MISSING],
        conflicting_requirements=requirement_counts[RequirementState.CONFLICTING],
        not_applicable_requirements=requirement_counts[RequirementState.NOT_APPLICABLE],
        contradictions=len(contradiction_references),
        uncertainties=len(uncertainty_references),
        limitations=len(limitations),
        nodes=len(ordered_nodes),
        edges=len(ordered_edges),
        maximum_depth=_maximum_depth(ordered_nodes, ordered_edges),
        requirements_complete=len(requirement_references)
        == len({item.requirement_evaluation_id for item in requirement_references}),
    )
    material = {
        "source_assessment_id": assessment.assessment_id,
        "assertion_id": assessment.assertion_id,
        "decision_status": assessment.state.value,
        "policy": None
        if policy_reference is None
        else (
            policy_reference.assertion_id,
            policy_reference.policy_version,
            policy_reference.registry_version,
        ),
        "nodes": tuple(item.node_id for item in ordered_nodes),
        "edges": tuple(item.edge_id for item in ordered_edges),
        "statements": tuple(item.statement_id for item in ordered_statements),
    }
    return DecisionTrace(
        identifier=TraceIdentifier(
            trace_id=trace_content_id("dtr", material),
            source_assessment_id=assessment.assessment_id,
        ),
        assertion_id=assessment.assertion_id,
        decision_status=assessment.state,
        policy_reference=policy_reference,
        evidence_references=evidence_references,
        identity_references=identity_references,
        correlation_references=correlation_references,
        requirement_references=requirement_references,
        contradiction_references=contradiction_references,
        uncertainty_references=uncertainty_references,
        limitations=limitations,
        nodes=ordered_nodes,
        edges=ordered_edges,
        explanation_statements=ordered_statements,
        summary=summary,
    )
