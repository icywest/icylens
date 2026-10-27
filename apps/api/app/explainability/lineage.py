from __future__ import annotations

from app.schemas.correlation import MultilayerCorrelationResult
from app.schemas.evidence import EvidenceBatch
from app.schemas.explainability import (
    CorrelationReferenceKind,
    IdentityReferenceKind,
    TraceContradictionReference,
    TraceCorrelationReference,
    TraceEvidenceReference,
    TraceIdentityReference,
    TraceLimitation,
    TracePolicyReference,
    TraceRequirementReference,
    TraceUncertaintyReference,
    trace_content_id,
)
from app.schemas.identity import IdentityResolutionResult, IdentityResolutionStatus
from app.schemas.sufficiency import SufficiencyAssertion, SufficiencyAssessment


def evidence_lineage(
    batch: EvidenceBatch, assessment: SufficiencyAssessment
) -> tuple[TraceEvidenceReference, ...]:
    selected = set(assessment.evidence_ids)
    return tuple(
        TraceEvidenceReference(
            evidence_id=record.identifier.evidence_id,
            source_module=record.source.module,
            source_phase=record.source.phase,
            origin_type=record.provenance.origin_type,
            trust_classification=record.provenance.trust_classification,
            synthetic=record.provenance.synthetic,
            origin_verified=record.provenance.origin_verified,
            verification_status=record.provenance.integrity_verification,
        )
        for record in batch.records
        if record.identifier.evidence_id in selected
    )


def policy_lineage(
    policy: SufficiencyAssertion | None,
) -> TracePolicyReference | None:
    if policy is None:
        return None
    return TracePolicyReference(
        assertion_id=policy.assertion_id,
        policy_version=policy.version,
    )


def identity_lineage(
    identity: IdentityResolutionResult,
    assessment: SufficiencyAssessment,
    policy: SufficiencyAssertion | None,
) -> tuple[TraceIdentityReference, ...]:
    if policy is None or policy.required_identity_type is None:
        return ()
    selected = set(assessment.evidence_ids)
    match_by_id = {item.match_id: item for item in identity.matches}
    references: dict[str, TraceIdentityReference] = {}
    for group in identity.groups:
        if (
            group.identity_type is policy.required_identity_type
            and group.namespace is policy.required_identity_namespace
            and selected.issubset(group.member_evidence_ids)
        ):
            supporting_match = match_by_id[group.supporting_match_ids[0]]
            references[group.group_id] = TraceIdentityReference(
                reference_kind=IdentityReferenceKind.GROUP,
                identity_object_id=group.group_id,
                rule_id=supporting_match.rule_id,
                status=IdentityResolutionStatus.SAME_IDENTITY,
                identity_type=group.identity_type,
                namespace=group.namespace,
                evidence_ids=tuple(
                    item for item in group.member_evidence_ids if item in selected
                ),
            )
    if references:
        return tuple(
            sorted(references.values(), key=lambda item: item.identity_object_id)
        )
    for match in identity.matches:
        if (
            match.identity_type is policy.required_identity_type
            and selected.intersection(match.evidence_ids)
        ):
            references[match.match_id] = TraceIdentityReference(
                reference_kind=IdentityReferenceKind.MATCH,
                identity_object_id=match.match_id,
                rule_id=match.rule_id,
                status=match.status,
                identity_type=match.identity_type,
                namespace=match.namespace,
                evidence_ids=tuple(
                    item for item in match.evidence_ids if item in selected
                ),
            )
    return tuple(sorted(references.values(), key=lambda item: item.identity_object_id))[
        :16
    ]


def correlation_lineage(
    correlation: MultilayerCorrelationResult,
    assessment: SufficiencyAssessment,
) -> tuple[TraceCorrelationReference, ...]:
    selected = set(assessment.evidence_ids)
    required_relationship_ids = {
        relationship_id
        for requirement in assessment.requirement_evaluations
        for relationship_id in requirement.supporting_relationship_ids
    }
    references: dict[str, TraceCorrelationReference] = {}
    for relationship in correlation.relationships:
        if relationship.relationship_id in required_relationship_ids:
            references[relationship.relationship_id] = TraceCorrelationReference(
                reference_kind=CorrelationReferenceKind.RELATIONSHIP,
                correlation_object_id=relationship.relationship_id,
                rule_id=relationship.rule_id,
                status=relationship.status,
                relationship_type=relationship.relationship_type,
                evidence_ids=tuple(
                    item for item in relationship.evidence_ids if item in selected
                ),
            )
    if references:
        return tuple(
            sorted(references.values(), key=lambda item: item.correlation_object_id)
        )
    candidate_by_id = {item.candidate_id: item for item in correlation.candidates}
    for evaluation in correlation.evaluations:
        candidate = candidate_by_id[evaluation.candidate_id]
        if set(candidate.evidence_ids) == selected:
            references[evaluation.evaluation_id] = TraceCorrelationReference(
                reference_kind=CorrelationReferenceKind.EVALUATION,
                correlation_object_id=evaluation.evaluation_id,
                rule_id=evaluation.rule_id,
                status=evaluation.status,
                relationship_type=None,
                evidence_ids=candidate.evidence_ids,
            )
    return tuple(
        sorted(references.values(), key=lambda item: item.correlation_object_id)
    )[:16]


def requirement_lineage(
    assessment: SufficiencyAssessment,
) -> tuple[TraceRequirementReference, ...]:
    return tuple(
        TraceRequirementReference(
            requirement_evaluation_id=item.evaluation_id,
            requirement_id=item.requirement_id,
            state=item.state,
            evidence_ids=item.supporting_evidence_ids,
            relationship_ids=item.supporting_relationship_ids,
        )
        for item in assessment.requirement_evaluations
    )


def contradiction_lineage(
    assessment: SufficiencyAssessment,
) -> tuple[TraceContradictionReference, ...]:
    return tuple(
        TraceContradictionReference(
            contradiction_id=item.contradiction_id,
            category=item.category,
            requirement_id=item.requirement_id,
            evidence_ids=item.evidence_ids,
            source_conflict_id=item.source_conflict_id,
        )
        for item in assessment.contradictions
    )


def uncertainty_lineage(
    assessment: SufficiencyAssessment,
) -> tuple[TraceUncertaintyReference, ...]:
    return tuple(
        TraceUncertaintyReference(
            uncertainty_id=item.uncertainty_id,
            category=item.category,
            evidence_ids=item.evidence_ids,
            affects_sufficiency=item.affects_sufficiency,
        )
        for item in assessment.uncertainty_reasons
    )


def limitation_lineage(
    assessment: SufficiencyAssessment,
) -> tuple[TraceLimitation, ...]:
    limitations = []
    for index, statement in enumerate(assessment.limitations, start=1):
        code = f"limitation_{index:03d}"
        material = {"limitation_code": code, "statement": statement}
        limitations.append(
            TraceLimitation(
                limitation_id=trace_content_id("tli", material),
                limitation_code=code,
                statement=statement,
            )
        )
    return tuple(limitations)
