from __future__ import annotations

from dataclasses import dataclass

from app.schemas.correlation import (
    CorrelationRelationship,
    CorrelationRelationshipType,
    MultilayerCorrelationResult,
)
from app.schemas.evidence import EvidenceBatch, EvidenceRecord
from app.schemas.identity import (
    IdentityConflict,
    IdentityConflictCode,
    IdentityResolutionResult,
    ResolvedIdentityGroup,
)
from app.schemas.sufficiency import AssertionSelection, SufficiencyAssertion

_NON_BLOCKING_IDENTITY_CONFLICTS = {
    IdentityConflictCode.MISSING_REQUIRED_ATTRIBUTE,
    IdentityConflictCode.UNSUPPORTED_NAMESPACE,
}


@dataclass(frozen=True, slots=True)
class AssessmentContext:
    batch: EvidenceBatch
    identity: IdentityResolutionResult
    correlation: MultilayerCorrelationResult
    records: dict[str, EvidenceRecord]


def build_assessment_context(
    batch: EvidenceBatch,
    identity: IdentityResolutionResult,
    correlation: MultilayerCorrelationResult,
) -> AssessmentContext:
    if identity.batch_id != batch.batch_id or correlation.batch_id != batch.batch_id:
        raise ValueError("trusted internal results must correspond to the exact batch")
    return AssessmentContext(
        batch=batch,
        identity=identity,
        correlation=correlation,
        records={item.identifier.evidence_id: item for item in batch.records},
    )


def selected_records(
    context: AssessmentContext, selection: AssertionSelection
) -> tuple[tuple[EvidenceRecord, ...], tuple[str, ...]]:
    found = tuple(
        context.records[evidence_id]
        for evidence_id in selection.evidence_ids
        if evidence_id in context.records
    )
    missing = tuple(
        evidence_id
        for evidence_id in selection.evidence_ids
        if evidence_id not in context.records
    )
    return found, missing


def supporting_identity_group(
    context: AssessmentContext,
    selection: AssertionSelection,
    policy: SufficiencyAssertion,
) -> ResolvedIdentityGroup | None:
    if policy.required_identity_type is None:
        return None
    selected = set(selection.evidence_ids)
    if len(selected) < 2:
        return None
    for group in context.identity.groups:
        if (
            group.identity_type is policy.required_identity_type
            and group.namespace is policy.required_identity_namespace
            and selected.issubset(group.member_evidence_ids)
        ):
            return group
    return None


def supporting_relationship(
    context: AssessmentContext,
    selection: AssertionSelection,
    relationship_type: CorrelationRelationshipType,
) -> CorrelationRelationship | None:
    selected = set(selection.evidence_ids)
    if len(selected) < 2:
        return None
    for relationship in context.correlation.relationships:
        if relationship.relationship_type is relationship_type and selected.issubset(
            relationship.evidence_ids
        ):
            return relationship
    return None


def relevant_identity_conflicts(
    context: AssessmentContext,
    selection: AssertionSelection,
    policy: SufficiencyAssertion,
) -> tuple[IdentityConflict, ...]:
    selected = set(selection.evidence_ids)
    relevant: list[IdentityConflict] = []
    for conflict in context.identity.conflicts:
        if not selected.intersection(conflict.evidence_ids):
            continue
        if conflict.code in _NON_BLOCKING_IDENTITY_CONFLICTS:
            continue
        if policy.required_identity_type is not None:
            if conflict.identity_type is policy.required_identity_type:
                relevant.append(conflict)
        elif (
            policy.required_relationship_type
            is CorrelationRelationshipType.EXPLICIT_EVIDENCE_REFERENCE
            and conflict.code
            in {
                IdentityConflictCode.DUPLICATE_EVIDENCE_REFERENCE,
                IdentityConflictCode.IDENTITY_REFERENCE_MISMATCH,
                IdentityConflictCode.CONTRADICTORY_PROVENANCE,
            }
        ):
            relevant.append(conflict)
    return tuple(sorted(relevant, key=lambda item: item.conflict_id))


def has_weak_context_match(
    context: AssessmentContext, selection: AssertionSelection
) -> bool:
    selected = set(selection.evidence_ids)
    return any(
        selected == set(candidate.evidence_ids)
        and candidate.rule_id == "CR-CONTEXT-001"
        for candidate in context.correlation.candidates
    )


def has_unsupported_relation(
    context: AssessmentContext, selection: AssertionSelection
) -> bool:
    selected = set(selection.evidence_ids)
    return any(
        selected == set(candidate.evidence_ids)
        and candidate.rule_id == "CR-UNSUPPORTED-001"
        for candidate in context.correlation.candidates
    )
