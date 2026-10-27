from __future__ import annotations

from app.correlation.rules import CorrelationRuleRegistry
from app.schemas.correlation import (
    MAX_CORRELATION_RELATIONSHIPS,
    CorrelationCandidate,
    CorrelationEvaluation,
    CorrelationEvidenceReference,
    CorrelationRelationship,
    CorrelationStatus,
    correlation_content_id,
)
from app.schemas.evidence import EvidenceBatch
from app.schemas.identity import IdentityResolutionResult


def build_relationships(
    candidates: tuple[CorrelationCandidate, ...],
    evaluations: tuple[CorrelationEvaluation, ...],
    batch: EvidenceBatch,
    identity: IdentityResolutionResult,
    registry: CorrelationRuleRegistry,
) -> tuple[tuple[CorrelationRelationship, ...], bool]:
    candidate_by_id = {item.candidate_id: item for item in candidates}
    record_by_id = {item.identifier.evidence_id: item for item in batch.records}
    group_by_id = {item.group_id: item for item in identity.groups}
    relationships: list[CorrelationRelationship] = []
    for evaluation in evaluations:
        if evaluation.status is not CorrelationStatus.SUPPORTED:
            continue
        candidate = candidate_by_id[evaluation.candidate_id]
        rule = registry.get(candidate.rule_id)
        if rule.relationship_type is None:
            continue
        group = (
            None
            if candidate.identity_group_id is None
            else group_by_id[candidate.identity_group_id]
        )
        references = tuple(
            CorrelationEvidenceReference(
                evidence_id=evidence_id,
                source_module=record_by_id[evidence_id].source.module,
                source_phase=record_by_id[evidence_id].source.phase,
                origin_type=record_by_id[evidence_id].provenance.origin_type,
                trust_classification=record_by_id[
                    evidence_id
                ].provenance.trust_classification,
                synthetic=record_by_id[evidence_id].provenance.synthetic,
                verification_status=record_by_id[
                    evidence_id
                ].provenance.integrity_verification,
                field_categories=(
                    "identity_and_context"
                    if group is not None
                    else "explicit_reference",
                ),
            )
            for evidence_id in candidate.evidence_ids
        )
        supporting_matches = () if group is None else group.supporting_match_ids[:16]
        material = {
            "rule_id": candidate.rule_id,
            "evaluation_id": evaluation.evaluation_id,
            "relationship_type": rule.relationship_type.value,
            "evidence_ids": candidate.evidence_ids,
            "identity_group_id": candidate.identity_group_id,
            "identity_match_ids": supporting_matches,
        }
        relationships.append(
            CorrelationRelationship(
                relationship_id=correlation_content_id("crr", material),
                rule_id=candidate.rule_id,
                evaluation_id=evaluation.evaluation_id,
                relationship_type=rule.relationship_type,
                evidence_ids=candidate.evidence_ids,
                identity_type=candidate.identity_type,
                namespace=candidate.namespace,
                supporting_identity_group_id=candidate.identity_group_id,
                supporting_identity_match_ids=supporting_matches,
                evidence_references=references,
                limitations=rule.limitations,
            )
        )
    ordered = tuple(sorted(relationships, key=lambda item: item.relationship_id))
    return (
        ordered[:MAX_CORRELATION_RELATIONSHIPS],
        len(ordered) > MAX_CORRELATION_RELATIONSHIPS,
    )
