from __future__ import annotations

from app.correlation.service import correlate_evidence_with_identity
from app.explainability.graph import build_decision_trace
from app.explainability.lineage import (
    contradiction_lineage,
    correlation_lineage,
    evidence_lineage,
    identity_lineage,
    limitation_lineage,
    policy_lineage,
    requirement_lineage,
    uncertainty_lineage,
)
from app.identity.resolution import resolve_identities
from app.schemas.correlation import (
    MultilayerCorrelationRequest,
    MultilayerCorrelationResult,
)
from app.schemas.explainability import DecisionTraceRequest, DecisionTraceResult
from app.schemas.identity import IdentityResolutionRequest, IdentityResolutionResult
from app.schemas.sufficiency import (
    SufficiencyAssessmentRequest,
    SufficiencyAssessmentResult,
)
from app.sufficiency.rules import DEFAULT_SUFFICIENCY_POLICY_REGISTRY
from app.sufficiency.service import assess_evidence_sufficiency_with_context


def explain_decisions(request: DecisionTraceRequest) -> DecisionTraceResult:
    identity = resolve_identities(IdentityResolutionRequest(batch=request.batch))
    correlation = correlate_evidence_with_identity(
        MultilayerCorrelationRequest(batch=request.batch), identity
    )
    sufficiency = assess_evidence_sufficiency_with_context(
        SufficiencyAssessmentRequest(
            batch=request.batch,
            assertions=request.assertions,
        ),
        identity,
        correlation,
    )
    return explain_decisions_with_context(request, identity, correlation, sufficiency)


def explain_decisions_with_context(
    request: DecisionTraceRequest,
    identity: IdentityResolutionResult,
    correlation: MultilayerCorrelationResult,
    sufficiency: SufficiencyAssessmentResult,
) -> DecisionTraceResult:
    """Build traces from backend-owned results bound to the exact request batch."""
    if not (
        request.batch.batch_id
        == identity.batch_id
        == correlation.batch_id
        == sufficiency.batch_id
    ):
        raise ValueError(
            "explainability prerequisites must correspond to the exact evidence batch"
        )
    assessment_by_key = {
        (item.assertion_id, item.evidence_ids): item for item in sufficiency.assessments
    }
    traces = []
    for selection in request.assertions:
        assessment = assessment_by_key[(selection.assertion_id, selection.evidence_ids)]
        policy = DEFAULT_SUFFICIENCY_POLICY_REGISTRY.find(selection.assertion_id)
        traces.append(
            build_decision_trace(
                assessment,
                policy_lineage(policy),
                evidence_lineage(request.batch, assessment),
                identity_lineage(identity, assessment, policy),
                correlation_lineage(correlation, assessment),
                requirement_lineage(assessment),
                contradiction_lineage(assessment),
                uncertainty_lineage(assessment),
                limitation_lineage(assessment),
            )
        )
    ordered = tuple(sorted(traces, key=lambda item: item.identifier.trace_id))
    return DecisionTraceResult(
        batch_id=request.batch.batch_id,
        traces=ordered,
        limitations=(
            "A decision trace documents software dependencies and does not prove that an external activity occurred.",
            "Explanation preserves the source assessment and cannot broaden its registered assertion or scientific limitations.",
            "Evidence provenance, synthetic status, contradictions and categorical uncertainty remain explicit and are never promoted.",
            "Trace edges are direct decision dependencies, not correlation edges, causal links, attack sequences, or inferred transitive relationships.",
            "Static templates contain no sample payload, telemetry, credentials, paths, commands, user, host, or network values.",
            "Deterministic identifiers demonstrate consistency with computed content; they do not independently authenticate origin and are not anonymous.",
        ),
    )
