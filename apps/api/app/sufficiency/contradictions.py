from __future__ import annotations

from app.schemas.identity import IdentityConflictCode
from app.schemas.sufficiency import (
    AssertionSelection,
    ContradictionCategory,
    EvidenceContradiction,
    SufficiencyAssertion,
    sufficiency_content_id,
)
from app.sufficiency.resolver import AssessmentContext, relevant_identity_conflicts


def evaluate_contradictions(
    context: AssessmentContext,
    selection: AssertionSelection,
    policy: SufficiencyAssertion,
) -> tuple[EvidenceContradiction, ...]:
    correlation_by_source = {
        item.source_identity_conflict_id: item for item in context.correlation.conflicts
    }
    contradictions: list[EvidenceContradiction] = []
    for conflict in relevant_identity_conflicts(context, selection, policy):
        correlation_conflict = correlation_by_source.get(conflict.conflict_id)
        source_conflict_id = (
            conflict.conflict_id
            if correlation_conflict is None
            else correlation_conflict.conflict_id
        )
        if conflict.code is IdentityConflictCode.DUPLICATE_EVIDENCE_REFERENCE:
            category = ContradictionCategory.DUPLICATE_REFERENCE
        elif correlation_conflict is not None:
            category = ContradictionCategory.CORRELATION_CONFLICT
        else:
            category = ContradictionCategory.IDENTITY_CONFLICT
        evidence_ids = tuple(sorted(conflict.evidence_ids))
        material = {
            "category": category.value,
            "assertion_id": selection.assertion_id,
            "requirement_id": "no_relevant_conflict",
            "evidence_ids": evidence_ids,
            "namespace": (
                None if conflict.namespace is None else conflict.namespace.value
            ),
            "source_conflict_id": source_conflict_id,
        }
        contradictions.append(
            EvidenceContradiction(
                contradiction_id=sufficiency_content_id("sct", material),
                category=category,
                assertion_id=selection.assertion_id,
                requirement_id="no_relevant_conflict",
                evidence_ids=evidence_ids,
                identity_namespace=conflict.namespace,
                source_conflict_id=source_conflict_id,
                explanation=(
                    "A retained conflict affects the identity or explicit reference required by this assertion; no source precedence is applied."
                ),
            )
        )
    return tuple(sorted(contradictions, key=lambda item: item.contradiction_id))[:4]
