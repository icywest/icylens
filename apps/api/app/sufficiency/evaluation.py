from __future__ import annotations

from app.schemas.sufficiency import (
    AssertionSelection,
    EvidenceContradiction,
    EvidenceGap,
    EvidenceGapCategory,
    EvidenceSupportReference,
    RequirementEvaluation,
    RequirementKind,
    RequirementState,
    SufficiencyAssertion,
    SufficiencyAssessment,
    SufficiencyState,
    UncertaintyReason,
    sufficiency_content_id,
)
from app.sufficiency.contradictions import evaluate_contradictions
from app.sufficiency.resolver import (
    AssessmentContext,
    selected_records,
    supporting_identity_group,
    supporting_relationship,
)
from app.sufficiency.uncertainty import classify_uncertainty


def _requirement_evaluation(
    requirement_id: str,
    state: RequirementState,
    evidence_ids: tuple[str, ...],
    relationship_ids: tuple[str, ...],
    explanation: str,
) -> RequirementEvaluation:
    material = {
        "requirement_id": requirement_id,
        "state": state.value,
        "evidence_ids": evidence_ids,
        "relationship_ids": relationship_ids,
    }
    return RequirementEvaluation(
        evaluation_id=sufficiency_content_id("sre", material),
        requirement_id=requirement_id,
        state=state,
        supporting_evidence_ids=evidence_ids,
        supporting_relationship_ids=relationship_ids,
        explanation=explanation,
    )


def _gap(
    category: EvidenceGapCategory,
    selection: AssertionSelection,
    requirement_id: str,
    missing_ids: tuple[str, ...],
    explanation: str,
) -> EvidenceGap:
    material = {
        "category": category.value,
        "assertion_id": selection.assertion_id,
        "requirement_id": requirement_id,
        "missing_evidence_ids": missing_ids,
    }
    return EvidenceGap(
        gap_id=sufficiency_content_id("sgp", material),
        category=category,
        assertion_id=selection.assertion_id,
        requirement_id=requirement_id,
        missing_evidence_ids=missing_ids,
        explanation=explanation,
    )


def _assessment_id(
    selection: AssertionSelection,
    policy_version: str | None,
    state: SufficiencyState,
    requirements: tuple[RequirementEvaluation, ...],
    contradictions: tuple[EvidenceContradiction, ...],
    gaps: tuple[EvidenceGap, ...],
    uncertainties: tuple[UncertaintyReason, ...],
) -> str:
    material = {
        "assertion_id": selection.assertion_id,
        "assertion_version": policy_version,
        "evidence_ids": selection.evidence_ids,
        "state": state.value,
        "requirements": tuple(item.evaluation_id for item in requirements),
        "contradictions": tuple(item.contradiction_id for item in contradictions),
        "gaps": tuple(item.gap_id for item in gaps),
        "uncertainties": tuple(item.uncertainty_id for item in uncertainties),
    }
    return sufficiency_content_id("sas", material)


def evaluate_assertion(
    context: AssessmentContext,
    selection: AssertionSelection,
    policy: SufficiencyAssertion | None,
) -> SufficiencyAssessment:
    records, missing_ids = selected_records(context, selection)
    if policy is None:
        uncertainties = classify_uncertainty(
            context,
            selection,
            None,
            identity_missing=False,
            has_contradictions=False,
        )
        state = SufficiencyState.UNSUPPORTED_ASSERTION
        return SufficiencyAssessment(
            assessment_id=_assessment_id(
                selection, None, state, (), (), (), uncertainties
            ),
            assertion_id=selection.assertion_id,
            assertion_version=None,
            statement="The requested assertion has no registered assessment policy.",
            state=state,
            evidence_ids=selection.evidence_ids,
            requirement_evaluations=(),
            support_references=(),
            contradictions=(),
            gaps=(),
            uncertainty_reasons=uncertainties,
            limitations=(
                "An unsupported assertion is not evaluated as false or as insufficient evidence.",
                "No relationship, threat fact, score, probability, or verdict is created to answer an unsupported assertion.",
            ),
        )

    domains_applicable = bool(records) and all(
        item.observation.domain in policy.applicable_domains for item in records
    )
    identity_group = supporting_identity_group(context, selection, policy)
    relationship = supporting_relationship(
        context, selection, policy.required_relationship_type
    )
    contradictions = evaluate_contradictions(context, selection, policy)
    selected_existing_ids = tuple(
        sorted(item.identifier.evidence_id for item in records)
    )
    relationship_ids = () if relationship is None else (relationship.relationship_id,)
    requirement_evaluations: list[RequirementEvaluation] = []
    gaps: list[EvidenceGap] = []

    for requirement in policy.requirements:
        if requirement.kind is RequirementKind.EVIDENCE_RECORD_EXISTS:
            requirement_state = (
                RequirementState.SATISFIED
                if not missing_ids
                else RequirementState.MISSING
            )
            explanation = (
                "Every selected evidence ID resolves inside the validated batch."
                if not missing_ids
                else "One or more selected evidence IDs are absent from the validated batch."
            )
            evidence_ids = selected_existing_ids
        elif not domains_applicable:
            requirement_state = RequirementState.NOT_APPLICABLE
            explanation = (
                "The selected evidence domains do not match this assertion policy."
            )
            evidence_ids = selected_existing_ids
        elif requirement.kind is RequirementKind.PROVENANCE_AVAILABLE:
            requirement_state = RequirementState.SATISFIED
            explanation = "Structured provenance is present and remains separate for every selected record."
            evidence_ids = selected_existing_ids
        elif requirement.kind is RequirementKind.IDENTITY_SATISFIED:
            if contradictions:
                requirement_state = RequirementState.CONFLICTING
                explanation = "A relevant retained conflict prevents the required identity from supporting this assertion."
            elif identity_group is None:
                requirement_state = RequirementState.MISSING
                explanation = "No exact 06.02 identity group satisfies the required type and namespace."
            else:
                requirement_state = RequirementState.SATISFIED
                explanation = "An exact 06.02 identity group satisfies the required type and namespace."
            evidence_ids = () if identity_group is None else selection.evidence_ids
        elif requirement.kind is RequirementKind.CORRELATION_SUPPORTED:
            if contradictions:
                requirement_state = RequirementState.CONFLICTING
                explanation = (
                    "A relevant conflict suppresses the required 06.03 relationship."
                )
            elif relationship is None:
                requirement_state = RequirementState.MISSING
                explanation = "No supported 06.03 relationship of the required type covers the selected evidence."
            else:
                requirement_state = RequirementState.SATISFIED
                explanation = "A supported 06.03 relationship of the required type covers the selected evidence."
            evidence_ids = () if relationship is None else selection.evidence_ids
        else:
            requirement_state = (
                RequirementState.CONFLICTING
                if contradictions
                else RequirementState.SATISFIED
            )
            explanation = (
                "A relevant retained conflict affects this assertion."
                if contradictions
                else "No relevant retained conflict affects this assertion."
            )
            evidence_ids = selection.evidence_ids
        evaluation = _requirement_evaluation(
            requirement.requirement_id,
            requirement_state,
            evidence_ids,
            relationship_ids
            if requirement.kind is RequirementKind.CORRELATION_SUPPORTED
            else (),
            explanation,
        )
        requirement_evaluations.append(evaluation)
        if requirement_state in {
            RequirementState.MISSING,
            RequirementState.NOT_APPLICABLE,
        }:
            category = {
                RequirementKind.EVIDENCE_RECORD_EXISTS: EvidenceGapCategory.MISSING_RECORD,
                RequirementKind.PROVENANCE_AVAILABLE: EvidenceGapCategory.MISSING_PROVENANCE,
                RequirementKind.IDENTITY_SATISFIED: EvidenceGapCategory.MISSING_IDENTITY,
                RequirementKind.CORRELATION_SUPPORTED: EvidenceGapCategory.MISSING_RELATIONSHIP,
                RequirementKind.NO_RELEVANT_CONFLICT: EvidenceGapCategory.INAPPLICABLE_DOMAIN,
            }[requirement.kind]
            if requirement_state is RequirementState.NOT_APPLICABLE:
                category = EvidenceGapCategory.INAPPLICABLE_DOMAIN
            gaps.append(
                _gap(
                    category,
                    selection,
                    requirement.requirement_id,
                    missing_ids
                    if category is EvidenceGapCategory.MISSING_RECORD
                    else (),
                    explanation,
                )
            )

    requirements = tuple(requirement_evaluations)
    ordered_gaps = tuple(sorted(gaps, key=lambda item: item.gap_id))
    if missing_ids:
        state = SufficiencyState.INSUFFICIENT_EVIDENCE
    elif not domains_applicable:
        state = SufficiencyState.NOT_APPLICABLE
    elif contradictions:
        state = SufficiencyState.CONFLICTING_EVIDENCE
    elif any(item.state is RequirementState.MISSING for item in requirements):
        state = SufficiencyState.INSUFFICIENT_EVIDENCE
    elif all(item.state is RequirementState.SATISFIED for item in requirements):
        state = SufficiencyState.SUFFICIENT
    else:
        state = SufficiencyState.NOT_APPLICABLE
    uncertainties = classify_uncertainty(
        context,
        selection,
        policy,
        identity_missing=identity_group is None,
        has_contradictions=bool(contradictions),
    )
    support_references = tuple(
        EvidenceSupportReference(
            evidence_id=record.identifier.evidence_id,
            source_module=record.source.module,
            origin_type=record.provenance.origin_type,
            trust_classification=record.provenance.trust_classification,
            synthetic=record.provenance.synthetic,
            verification_status=record.provenance.integrity_verification,
            relationship_id=None
            if relationship is None
            else relationship.relationship_id,
            safe_categories=(policy.category.value, "provenance"),
        )
        for record in records
    )
    return SufficiencyAssessment(
        assessment_id=_assessment_id(
            selection,
            policy.version,
            state,
            requirements,
            contradictions,
            ordered_gaps,
            uncertainties,
        ),
        assertion_id=selection.assertion_id,
        assertion_version=policy.version,
        statement=policy.statement,
        state=state,
        evidence_ids=selection.evidence_ids,
        requirement_evaluations=requirements,
        support_references=support_references,
        contradictions=contradictions,
        gaps=ordered_gaps,
        uncertainty_reasons=uncertainties,
        limitations=policy.limitations,
    )
