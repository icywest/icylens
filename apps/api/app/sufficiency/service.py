from __future__ import annotations

from app.correlation.service import correlate_evidence_with_identity
from app.identity.resolution import resolve_identities
from app.schemas.correlation import (
    MultilayerCorrelationRequest,
    MultilayerCorrelationResult,
)
from app.schemas.identity import IdentityResolutionRequest, IdentityResolutionResult
from app.schemas.sufficiency import (
    SufficiencyAssessmentRequest,
    SufficiencyAssessmentResult,
    SufficiencyState,
    SufficiencySummary,
)
from app.sufficiency.evaluation import evaluate_assertion
from app.sufficiency.resolver import build_assessment_context
from app.sufficiency.rules import (
    DEFAULT_SUFFICIENCY_POLICY_REGISTRY,
    SufficiencyPolicyRegistry,
)


def assess_evidence_sufficiency(
    request: SufficiencyAssessmentRequest,
    *,
    registry: SufficiencyPolicyRegistry = DEFAULT_SUFFICIENCY_POLICY_REGISTRY,
) -> SufficiencyAssessmentResult:
    identity = resolve_identities(IdentityResolutionRequest(batch=request.batch))
    correlation = correlate_evidence_with_identity(
        MultilayerCorrelationRequest(batch=request.batch), identity
    )
    return assess_evidence_sufficiency_with_context(
        request, identity, correlation, registry=registry
    )


def assess_evidence_sufficiency_with_context(
    request: SufficiencyAssessmentRequest,
    identity: IdentityResolutionResult,
    correlation: MultilayerCorrelationResult,
    *,
    registry: SufficiencyPolicyRegistry = DEFAULT_SUFFICIENCY_POLICY_REGISTRY,
) -> SufficiencyAssessmentResult:
    """Compose backend-produced prerequisite results after exact batch binding."""
    context = build_assessment_context(request.batch, identity, correlation)
    assessments = tuple(
        sorted(
            (
                evaluate_assertion(
                    context, selection, registry.find(selection.assertion_id)
                )
                for selection in request.assertions
            ),
            key=lambda item: item.assessment_id,
        )
    )
    counts = {state: 0 for state in SufficiencyState}
    for assessment in assessments:
        counts[assessment.state] += 1
    summary = SufficiencySummary(
        evidence_records=len(request.batch.records),
        requested_assertions=len(assessments),
        sufficient=counts[SufficiencyState.SUFFICIENT],
        insufficient_evidence=counts[SufficiencyState.INSUFFICIENT_EVIDENCE],
        conflicting_evidence=counts[SufficiencyState.CONFLICTING_EVIDENCE],
        not_applicable=counts[SufficiencyState.NOT_APPLICABLE],
        unsupported_assertion=counts[SufficiencyState.UNSUPPORTED_ASSERTION],
        gaps=sum(len(item.gaps) for item in assessments),
        contradictions=sum(len(item.contradictions) for item in assessments),
        uncertainty_reasons=sum(len(item.uncertainty_reasons) for item in assessments),
        limits_reached=(
            identity.summary.comparisons_truncated or correlation.summary.limits_reached
        ),
    )
    return SufficiencyAssessmentResult(
        batch_id=request.batch.batch_id,
        assessments=assessments,
        summary=summary,
        limitations=(
            "Sufficiency is relative to one registered assertion and does not establish universal certainty or truth outside that policy.",
            "Insufficient evidence is not proof that an assertion is false; unsupported assertions are not evaluated by substitute policies.",
            "Categorical uncertainty is not probability, confidence, severity, ranking, or risk.",
            "Correlation is not causality, compatible context is not identity, and temporal proximity is not evaluated as a sequence.",
            "Synthetic and declared provenance remain explicit and are never promoted to authenticated operational observation.",
            "The engine does not confirm attacks, malware, compromise, exploitation, execution, persistence, command and control, or ATT&CK execution.",
            "Deterministic identifiers remain correlatable and are privacy minimized, not anonymous.",
        ),
    )
