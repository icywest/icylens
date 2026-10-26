from __future__ import annotations

from uuid import NAMESPACE_URL, UUID, uuid5

from app.schemas.behavior_correlation import RelationshipEvidence, RelationshipType

_NAMESPACE = uuid5(NAMESPACE_URL, "https://icylens.local/behavior/correlation/v1")


def relationship_id(
    relationship_type: RelationshipType, source_event_id: UUID, target_event_id: UUID
) -> UUID:
    return uuid5(
        _NAMESPACE,
        f"relationship:{relationship_type.value}:{source_event_id}:{target_event_id}",
    )


def sequence_id(
    relationship_type: RelationshipType, event_ids: tuple[UUID, ...]
) -> UUID:
    members = ":".join(str(event_id) for event_id in event_ids)
    return uuid5(_NAMESPACE, f"sequence:{relationship_type.value}:{members}")


def evidence(criterion: str, *facts: str) -> tuple[RelationshipEvidence, ...]:
    return (RelationshipEvidence(criterion=criterion, facts=facts),)
