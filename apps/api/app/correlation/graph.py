from __future__ import annotations

from app.schemas.correlation import (
    MAX_CORRELATION_GRAPH_EDGES,
    CorrelationGraphEdge,
    CorrelationGraphNode,
    CorrelationRelationship,
    correlation_content_id,
)
from app.schemas.evidence import EvidenceBatch


def build_graph(
    batch: EvidenceBatch,
    relationships: tuple[CorrelationRelationship, ...],
) -> tuple[tuple[CorrelationGraphNode, ...], tuple[CorrelationGraphEdge, ...], bool]:
    nodes = tuple(
        sorted(
            (
                CorrelationGraphNode(
                    node_id=record.identifier.evidence_id,
                    evidence_id=record.identifier.evidence_id,
                    source_module=record.source.module,
                    origin_type=record.provenance.origin_type,
                    trust_classification=record.provenance.trust_classification,
                    synthetic=record.provenance.synthetic,
                )
                for record in batch.records
            ),
            key=lambda item: item.node_id,
        )
    )
    edges: list[CorrelationGraphEdge] = []
    for relationship in relationships:
        anchor = relationship.evidence_ids[0]
        for target in relationship.evidence_ids[1:]:
            material = {
                "relationship_id": relationship.relationship_id,
                "rule_id": relationship.rule_id,
                "relationship_type": relationship.relationship_type.value,
                "source": anchor,
                "target": target,
            }
            edges.append(
                CorrelationGraphEdge(
                    edge_id=correlation_content_id("crg", material),
                    relationship_id=relationship.relationship_id,
                    rule_id=relationship.rule_id,
                    relationship_type=relationship.relationship_type,
                    source_node_id=anchor,
                    target_node_id=target,
                    evidence_references=(anchor, target),
                )
            )
    ordered = tuple(sorted(edges, key=lambda item: item.edge_id))
    return (
        nodes,
        ordered[:MAX_CORRELATION_GRAPH_EDGES],
        len(ordered) > MAX_CORRELATION_GRAPH_EDGES,
    )
