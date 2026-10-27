from __future__ import annotations

from app.correlation.candidates import select_candidates
from app.correlation.evaluation import evaluate_candidates
from app.correlation.graph import build_graph
from app.correlation.relationships import build_relationships
from app.correlation.rules import (
    DEFAULT_CORRELATION_RULE_REGISTRY,
    CorrelationRuleRegistry,
)
from app.identity.resolution import resolve_identities
from app.schemas.correlation import (
    MAX_CORRELATION_CONFLICTS,
    CorrelationConflict,
    CorrelationStatus,
    CorrelationSummary,
    MultilayerCorrelationRequest,
    MultilayerCorrelationResult,
    correlation_content_id,
)
from app.schemas.identity import IdentityResolutionRequest, IdentityResolutionResult


def correlate_evidence(
    request: MultilayerCorrelationRequest,
    *,
    registry: CorrelationRuleRegistry = DEFAULT_CORRELATION_RULE_REGISTRY,
) -> MultilayerCorrelationResult:
    identity = resolve_identities(IdentityResolutionRequest(batch=request.batch))
    return correlate_evidence_with_identity(request, identity, registry=registry)


def correlate_evidence_with_identity(
    request: MultilayerCorrelationRequest,
    identity: IdentityResolutionResult,
    *,
    registry: CorrelationRuleRegistry = DEFAULT_CORRELATION_RULE_REGISTRY,
) -> MultilayerCorrelationResult:
    """Compose a backend-produced identity result after exact batch binding."""
    if identity.batch_id != request.batch.batch_id:
        raise ValueError("identity result must correspond to the exact evidence batch")
    selection = select_candidates(request.batch, identity)
    evaluations = evaluate_candidates(
        selection.candidates, request.batch, identity, registry
    )
    relationships, relationships_truncated = build_relationships(
        selection.candidates, evaluations, request.batch, identity, registry
    )
    nodes, edges, edges_truncated = build_graph(request.batch, relationships)

    all_conflicts = []
    for source in identity.conflicts:
        material = {
            "source_identity_conflict_id": source.conflict_id,
            "evidence_ids": source.evidence_ids,
            "fields": source.field_categories,
        }
        all_conflicts.append(
            CorrelationConflict(
                conflict_id=correlation_content_id("crf", material),
                source_identity_conflict_id=source.conflict_id,
                evidence_ids=source.evidence_ids,
                field_categories=source.field_categories,
                explanation=source.explanation,
            )
        )
    ordered_conflicts = tuple(sorted(all_conflicts, key=lambda item: item.conflict_id))
    conflicts = ordered_conflicts[:MAX_CORRELATION_CONFLICTS]
    counts = {status: 0 for status in CorrelationStatus}
    for evaluation in evaluations:
        counts[evaluation.status] += 1
    limits_reached = (
        selection.truncated
        or relationships_truncated
        or edges_truncated
        or len(ordered_conflicts) > MAX_CORRELATION_CONFLICTS
        or identity.summary.comparisons_truncated
    )
    summary = CorrelationSummary(
        evidence_records=len(request.batch.records),
        candidates=len(selection.candidates),
        evaluations=len(evaluations),
        supported=counts[CorrelationStatus.SUPPORTED],
        insufficient_evidence=counts[CorrelationStatus.INSUFFICIENT_EVIDENCE],
        conflicting_evidence=counts[CorrelationStatus.CONFLICTING_EVIDENCE],
        not_applicable=counts[CorrelationStatus.NOT_APPLICABLE],
        unsupported_relation=counts[CorrelationStatus.UNSUPPORTED_RELATION],
        relationships=len(relationships),
        conflicts=len(conflicts),
        graph_nodes=len(nodes),
        graph_edges=len(edges),
        limits_reached=limits_reached,
    )
    return MultilayerCorrelationResult(
        batch_id=request.batch.batch_id,
        candidates=selection.candidates,
        evaluations=evaluations,
        relationships=relationships,
        conflicts=conflicts,
        graph_nodes=nodes,
        graph_edges=edges,
        summary=summary,
        limitations=(
            "Correlation is categorical and rule based; it emits no probability, confidence, ranking, or risk score.",
            "Only exact 06.02 identity groups and explicit 06.01 references can create relationships.",
            "Compatible context, common batch membership, temporal proximity, labels, predictions, and ATT&CK candidates cannot create edges.",
            "Graph edges are direct rule-supported projections only; no transitive, causal, temporal, threat, exploitation, or attack inference is performed.",
            "Per-record origin, trust, synthetic status, and verification remain separate and are never promoted.",
            "Identifiers are deterministic correlatable digests and are privacy minimized, not anonymous.",
        ),
    )
