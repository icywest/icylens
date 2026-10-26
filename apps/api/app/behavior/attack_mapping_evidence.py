from __future__ import annotations

from collections.abc import Sequence
from uuid import NAMESPACE_URL, UUID, uuid5

from app.schemas.attack_mapping import (
    MappingEvidenceReference,
    MappingEvidenceStrength,
    MappingEvidenceType,
)
from app.schemas.behavior import EventNature, EventUnion
from app.schemas.behavior_correlation import (
    EventRelationship,
    RelationshipConfidence,
    TemporalCorrelationResult,
)
from app.schemas.behavior_rules import (
    RuleEvaluationResult,
    RuleFinding,
    RuleMatchStatus,
)

_NAMESPACE = uuid5(NAMESPACE_URL, "https://icylens.local/behavior/attack-mapping/v1")


def finding_reference_id(finding: RuleFinding) -> UUID:
    members = ":".join(str(event_id) for event_id in sorted(finding.event_ids))
    return uuid5(
        _NAMESPACE,
        f"finding:{finding.rule_id}:{finding.rule_version}:{finding.result.value}:{members}",
    )


def find_rule_finding(result: RuleEvaluationResult, rule_id: str) -> RuleFinding | None:
    return next((item for item in result.findings if item.rule_id == rule_id), None)


def rule_reference(finding: RuleFinding) -> MappingEvidenceReference | None:
    if finding.result is not RuleMatchStatus.MATCHED:
        return None
    return MappingEvidenceReference(
        evidence_type=MappingEvidenceType.RULE_FINDING,
        reference_id=str(finding_reference_id(finding)),
        event_ids=tuple(sorted(finding.event_ids))[:8],
        nature=tuple(sorted(finding.event_natures, key=lambda item: item.value)),
        strength=MappingEvidenceStrength.STRONG,
        facts=(
            f"rule_id={finding.rule_id}",
            f"rule_version={finding.rule_version}",
            "result=matched",
        ),
    )


def _strength(value: RelationshipConfidence) -> MappingEvidenceStrength:
    return MappingEvidenceStrength(value.value)


def relationship_references(
    result: TemporalCorrelationResult,
    relationship_type: str,
    relevant_event_ids: set[UUID],
    events: Sequence[EventUnion],
) -> tuple[MappingEvidenceReference, ...]:
    nature_by_id: dict[UUID, EventNature] = {
        event.event_id: event.provenance.nature for event in events
    }
    references: list[MappingEvidenceReference] = []
    for relationship in result.relationships:
        if relationship.relationship_type.value != relationship_type:
            continue
        relationship_ids = {
            relationship.source_event_id,
            relationship.target_event_id,
        }
        if relevant_event_ids and relationship_ids.isdisjoint(relevant_event_ids):
            continue
        references.append(_relationship_reference(relationship, nature_by_id))
    return tuple(references[:8])


def _relationship_reference(
    relationship: EventRelationship, nature_by_id: dict[UUID, EventNature]
) -> MappingEvidenceReference:
    event_ids = (relationship.source_event_id, relationship.target_event_id)
    return MappingEvidenceReference(
        evidence_type=MappingEvidenceType.TEMPORAL_RELATIONSHIP,
        reference_id=str(relationship.relationship_id),
        event_ids=event_ids,
        nature=tuple(
            dict.fromkeys(
                nature_by_id[event_id]
                for event_id in event_ids
                if event_id in nature_by_id
            )
        ),
        strength=_strength(relationship.confidence),
        facts=(
            f"relationship_type={relationship.relationship_type.value}",
            f"state={relationship.state.value}",
            f"window={relationship.window_assessment.value}",
            "causal=false",
        ),
    )
