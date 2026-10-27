from __future__ import annotations

from app.correlation.rules import CorrelationRuleRegistry
from app.schemas.correlation import (
    CorrelationCandidate,
    CorrelationCandidateSource,
    CorrelationEvaluation,
    CorrelationRequirementEvaluation,
    CorrelationRequirementKind,
    CorrelationRequirementStatus,
    CorrelationStatus,
    correlation_content_id,
)
from app.schemas.evidence import EvidenceBatch
from app.schemas.identity import (
    IdentityConflictCode,
    IdentityResolutionResult,
    IdentityResolutionStatus,
)


def _status_for_candidate(
    candidate: CorrelationCandidate,
    identity: IdentityResolutionResult,
    conflicting_ids: tuple[str, ...],
) -> CorrelationStatus:
    if conflicting_ids:
        return CorrelationStatus.CONFLICTING_EVIDENCE
    if candidate.source is CorrelationCandidateSource.IDENTITY_GROUP:
        return (
            CorrelationStatus.SUPPORTED
            if candidate.rule_id != "CR-UNSUPPORTED-001"
            else CorrelationStatus.UNSUPPORTED_RELATION
        )
    if candidate.source is CorrelationCandidateSource.EXPLICIT_REFERENCE:
        return CorrelationStatus.SUPPORTED
    match_by_id = {item.match_id: item for item in identity.matches}
    if candidate.identity_match_id is None:
        raise ValueError("identity-match candidate is missing its source match")
    match = match_by_id[candidate.identity_match_id]
    return {
        IdentityResolutionStatus.COMPATIBLE_CONTEXT: CorrelationStatus.NOT_APPLICABLE,
        IdentityResolutionStatus.INSUFFICIENT_EVIDENCE: CorrelationStatus.INSUFFICIENT_EVIDENCE,
        IdentityResolutionStatus.CONFLICTING_IDENTITY: CorrelationStatus.CONFLICTING_EVIDENCE,
        IdentityResolutionStatus.NOT_COMPARABLE: CorrelationStatus.UNSUPPORTED_RELATION,
        IdentityResolutionStatus.SAME_IDENTITY: CorrelationStatus.UNSUPPORTED_RELATION,
    }[match.status]


def evaluate_candidates(
    candidates: tuple[CorrelationCandidate, ...],
    batch: EvidenceBatch,
    identity: IdentityResolutionResult,
    registry: CorrelationRuleRegistry,
) -> tuple[CorrelationEvaluation, ...]:
    del batch  # Batch validity and explicit reference closure are enforced by 06.01.
    evaluations: list[CorrelationEvaluation] = []
    for candidate in candidates:
        candidate_ids = set(candidate.evidence_ids)
        relevant_conflicts = tuple(
            sorted(
                conflict.conflict_id
                for conflict in identity.conflicts
                if candidate_ids.intersection(conflict.evidence_ids)
                and conflict.code
                not in {
                    IdentityConflictCode.MISSING_REQUIRED_ATTRIBUTE,
                    IdentityConflictCode.UNSUPPORTED_NAMESPACE,
                }
            )
        )[:16]
        rule = registry.get(candidate.rule_id)
        status = _status_for_candidate(candidate, identity, relevant_conflicts)
        requirements: list[CorrelationRequirementEvaluation] = []
        for requirement in rule.requirements:
            if requirement.kind is CorrelationRequirementKind.NO_IDENTITY_CONFLICT:
                requirement_status = (
                    CorrelationRequirementStatus.CONTRADICTORY
                    if relevant_conflicts
                    else CorrelationRequirementStatus.SATISFIED
                )
                explanation = (
                    "Retained identity conflicts contradict this candidate."
                    if relevant_conflicts
                    else "No retained identity conflict contradicts this candidate."
                )
            elif requirement.kind is CorrelationRequirementKind.PROVENANCE_PRESERVED:
                requirement_status = CorrelationRequirementStatus.SATISFIED
                explanation = (
                    "Original per-record provenance remains attached and unranked."
                )
            elif status is CorrelationStatus.SUPPORTED:
                requirement_status = CorrelationRequirementStatus.SATISFIED
                explanation = "The required explicit, typed support is present."
            elif status is CorrelationStatus.CONFLICTING_EVIDENCE:
                requirement_status = CorrelationRequirementStatus.CONTRADICTORY
                explanation = "The retained evidence conflicts with this requirement."
            elif status is CorrelationStatus.INSUFFICIENT_EVIDENCE:
                requirement_status = CorrelationRequirementStatus.MISSING
                explanation = "The required typed evidence is unavailable."
            else:
                requirement_status = CorrelationRequirementStatus.NOT_APPLICABLE
                explanation = (
                    "This requirement cannot establish a supported relationship."
                )
            requirements.append(
                CorrelationRequirementEvaluation(
                    requirement_id=requirement.requirement_id,
                    status=requirement_status,
                    explanation=explanation,
                )
            )
        material = {
            "candidate_id": candidate.candidate_id,
            "rule_id": candidate.rule_id,
            "status": status.value,
            "requirements": tuple(
                (item.requirement_id, item.status.value) for item in requirements
            ),
            "conflicts": relevant_conflicts,
        }
        explanation = rule.explanation_template
        if status is CorrelationStatus.CONFLICTING_EVIDENCE:
            explanation = "Retained identity evidence conflicts; no correlation relationship is emitted."
        elif status is CorrelationStatus.INSUFFICIENT_EVIDENCE:
            explanation = "Required typed identity evidence is unavailable; no relationship is emitted."
        evaluations.append(
            CorrelationEvaluation(
                evaluation_id=correlation_content_id("cre", material),
                candidate_id=candidate.candidate_id,
                rule_id=candidate.rule_id,
                status=status,
                requirement_evaluations=tuple(requirements),
                identity_conflict_ids=relevant_conflicts,
                explanation=explanation,
                limitations=rule.limitations,
                relationship_supported=status is CorrelationStatus.SUPPORTED,
            )
        )
    return tuple(sorted(evaluations, key=lambda item: item.evaluation_id))
