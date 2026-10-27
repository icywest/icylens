from __future__ import annotations

import inspect
import json
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.correlation import correlate_evidence
from app.correlation.candidates import select_candidates
from app.correlation.rules import (
    BUILTIN_CORRELATION_RULES,
    DEFAULT_CORRELATION_RULE_REGISTRY,
    CorrelationRuleRegistry,
    CorrelationRuleRegistryError,
)
from app.evidence.adapters import (
    adapt_ml_inference,
    adapt_static_analysis,
    adapt_vulnerability_intelligence,
    create_evidence_batch,
)
from app.identity.resolution import resolve_identities
from app.schemas.correlation import (
    MAX_CORRELATION_CANDIDATES,
    MAX_CORRELATION_EVALUATIONS,
    MAX_CORRELATION_GRAPH_EDGES,
    MAX_CORRELATION_OUTPUT_BYTES,
    MAX_CORRELATION_RELATIONSHIPS,
    CorrelationCandidate,
    CorrelationConflict,
    CorrelationEvaluation,
    CorrelationGraphEdge,
    CorrelationGraphNode,
    CorrelationRelationship,
    CorrelationRelationshipType,
    CorrelationRule,
    CorrelationStatus,
    MultilayerCorrelationRequest,
    MultilayerCorrelationResult,
    correlation_content_id,
)
from app.schemas.evidence import (
    EvidenceRecord,
    EvidenceReference,
    EvidenceReferenceProvenance,
    EvidenceReferenceType,
    EvidenceSubjectReference,
    EvidenceVerificationStatus,
)
from app.schemas.identity import IdentityResolutionRequest
from tests.test_identity_resolution import (
    _rebuild_record,
    _second_static,
    _second_vulnerability,
)
from tests.test_unified_evidence import ml_source, static_source, vulnerability_source


def _correlate(*records: EvidenceRecord) -> MultilayerCorrelationResult:
    batch = create_evidence_batch(tuple(records))
    return correlate_evidence(MultilayerCorrelationRequest(batch=batch))


def _reference(
    source: EvidenceRecord,
    target: EvidenceRecord,
    reference_type: EvidenceReferenceType = EvidenceReferenceType.EXPLICIT_DERIVATION,
) -> EvidenceRecord:
    link = EvidenceReference(
        source_evidence_id=source.identifier.evidence_id,
        referenced_evidence_id=target.identifier.evidence_id,
        reference_type=reference_type,
        provenance=EvidenceReferenceProvenance(
            established_by="explicit_source_contract",
            origin_type=source.provenance.origin_type,
            description="Explicit bounded test reference.",
        ),
        identity_assumptions=("No identity or causality is inferred.",),
        verification_status=EvidenceVerificationStatus.STRUCTURALLY_VALID,
    )
    return source.model_copy(update={"references": (*source.references, link)})


def _second_ml(*, same_analysis: bool = True) -> EvidenceRecord:
    source = ml_source().model_copy(
        update={
            "inference_id": UUID("60000000-0000-4000-8000-000000000006"),
            "analysis_id": (
                ml_source().analysis_id
                if same_analysis
                else UUID("70000000-0000-4000-8000-000000000007")
            ),
        }
    )
    return adapt_ml_inference(source)


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        ("content", CorrelationRelationshipType.SHARED_CONTENT_IDENTITY),
        ("cve", CorrelationRelationshipType.SHARED_VULNERABILITY_IDENTITY),
        ("analysis", CorrelationRelationshipType.SHARED_ANALYSIS_CONTEXT),
    ],
)
def test_exact_identity_groups_create_only_supported_relationships(
    kind: str, expected: CorrelationRelationshipType
) -> None:
    if kind == "content":
        records = (adapt_static_analysis(static_source()), _second_static())
    elif kind == "cve":
        records = (
            adapt_vulnerability_intelligence(vulnerability_source()),
            _second_vulnerability(),
        )
    else:
        records = (adapt_ml_inference(ml_source()), _second_ml())
    result = _correlate(*records)
    assert any(item.relationship_type is expected for item in result.relationships)
    assert all(
        item.status is CorrelationStatus.SUPPORTED for item in result.relationships
    )
    assert result.risk_score_generated is False
    assert result.causal_inference_performed is False


@pytest.mark.parametrize("reference_type", list(EvidenceReferenceType))
def test_explicit_references_create_declared_noncausal_relationship(
    reference_type: EvidenceReferenceType,
) -> None:
    first = adapt_static_analysis(static_source())
    second = _second_static()
    if reference_type is EvidenceReferenceType.EXPLICIT_SAME_SUBJECT:
        linked = _reference(second, first, reference_type)
    else:
        ml = adapt_ml_inference(ml_source())
        first, linked = first, _reference(ml, first, reference_type)
    result = _correlate(first, linked)
    relationship = next(
        item
        for item in result.relationships
        if item.relationship_type
        is CorrelationRelationshipType.EXPLICIT_EVIDENCE_REFERENCE
    )
    assert relationship.causal_relationship_inferred is False
    assert relationship.temporal_sequence_inferred is False
    assert relationship.trust_promoted is False


def test_compatible_context_is_auxiliary_and_creates_no_edge() -> None:
    static = adapt_static_analysis(static_source())
    ml = _reference(adapt_ml_inference(ml_source()), static)
    result = _correlate(static, ml)
    contextual = [
        item for item in result.evaluations if item.rule_id == "CR-CONTEXT-001"
    ]
    assert contextual and contextual[0].status is CorrelationStatus.NOT_APPLICABLE
    assert all(
        item.relationship_type
        is not CorrelationRelationshipType.SHARED_ANALYSIS_CONTEXT
        for item in result.relationships
    )


@pytest.mark.parametrize(
    "scenario",
    [
        "same_batch_only",
        "same_time_only",
        "same_label_only",
        "same_model_unversioned",
        "different_hash",
        "different_cve",
        "cross_module_uuid",
        "ml_prediction",
        "behavioral_count",
        "provider_value",
        "unknown_namespace",
    ],
)
def test_negative_matrix_never_invents_positive_relationship(scenario: str) -> None:
    first = adapt_static_analysis(static_source())
    if scenario == "different_hash":
        second = _second_static(sha256="b" * 64)
    elif scenario == "different_cve":
        second_source = vulnerability_source().model_copy(
            update={"cve_id": "CVE-2026-9999"}
        )
        second = adapt_vulnerability_intelligence(second_source)
        first = adapt_vulnerability_intelligence(vulnerability_source())
    elif scenario in {"same_model_unversioned", "ml_prediction"}:
        first, second = adapt_ml_inference(ml_source()), _second_ml(same_analysis=False)
    elif scenario == "unknown_namespace":
        second = _rebuild_record(
            first,
            subject=EvidenceSubjectReference(
                subject_type="file_content",
                namespace="sha1",
                value="b" * 40,
                identity_strength="declared",
                verified=False,
                scope="accepted_byte_stream_only",
            ),
        )
    else:
        second = adapt_ml_inference(ml_source())
    result = _correlate(first, second)
    assert not result.relationships
    assert not result.graph_edges
    assert result.summary.supported == 0


def test_duplicate_explicit_reference_is_preserved_as_conflict_and_suppressed() -> None:
    static = adapt_static_analysis(static_source())
    ml = _reference(adapt_ml_inference(ml_source()), static)
    duplicated = ml.model_copy(update={"references": ml.references * 2})
    result = _correlate(static, duplicated)
    assert result.conflicts
    assert any(
        item.status is CorrelationStatus.CONFLICTING_EVIDENCE
        for item in result.evaluations
    )
    assert not result.relationships


def test_dangling_and_circular_references_are_rejected_before_correlation() -> None:
    first = adapt_static_analysis(static_source())
    second = _second_static()
    dangling = EvidenceReference(
        source_evidence_id=first.identifier.evidence_id,
        referenced_evidence_id="evd_" + "0" * 64,
        reference_type=EvidenceReferenceType.EXPLICIT_DERIVATION,
        provenance=EvidenceReferenceProvenance(
            established_by="backend_validation",
            origin_type=first.provenance.origin_type,
            description="Deliberately dangling reference.",
        ),
        identity_assumptions=("No identity assumption.",),
        verification_status=EvidenceVerificationStatus.STRUCTURALLY_VALID,
    )
    with pytest.raises(ValidationError, match="resolve inside"):
        create_evidence_batch((first.model_copy(update={"references": (dangling,)}),))

    with pytest.raises(ValidationError, match="circular"):
        create_evidence_batch((_reference(first, second), _reference(second, first)))


def test_mismatched_same_subject_reference_is_rejected_by_evidence_boundary() -> None:
    static = adapt_static_analysis(static_source())
    vulnerability = adapt_vulnerability_intelligence(vulnerability_source())
    mismatched = _reference(
        vulnerability, static, EvidenceReferenceType.EXPLICIT_SAME_SUBJECT
    )
    with pytest.raises(ValidationError, match="identity mismatch"):
        create_evidence_batch((static, mismatched))


def test_conflicting_identity_is_visible_and_cannot_form_relationship() -> None:
    first = adapt_static_analysis(static_source())
    changed_source = static_source().model_copy(
        update={
            "fingerprint": static_source().fingerprint.model_copy(
                update={"sha256": "b" * 64}
            )
        }
    )
    second = adapt_static_analysis(changed_source)
    result = _correlate(first, second)
    assert result.conflicts
    assert result.summary.conflicting_evidence >= 1
    assert not result.relationships


@pytest.mark.parametrize(
    "field",
    [
        "persistence_performed",
        "causal_inference_performed",
        "temporal_sequence_inferred",
        "threat_verdict_generated",
        "risk_score_generated",
        "attack_finding_generated",
        "exploitation_inferred",
        "ml_promoted_to_observation",
        "trust_promoted",
    ],
)
def test_hard_safety_flags_are_always_false(field: str) -> None:
    result = _correlate(adapt_static_analysis(static_source()), _second_static())
    assert getattr(result, field) is False


def test_three_member_identity_group_is_linear_not_all_pairs_or_transitive() -> None:
    first = adapt_static_analysis(static_source())
    second = _second_static()
    third_source = static_source().model_copy(
        update={"analysis_id": UUID("80000000-0000-4000-8000-000000000008")}
    )
    third = adapt_static_analysis(third_source)
    result = _correlate(first, second, third)
    content = [
        item
        for item in result.relationships
        if item.relationship_type is CorrelationRelationshipType.SHARED_CONTENT_IDENTITY
    ]
    assert len(content) == 1
    assert len(content[0].evidence_ids) == 3
    edges = [
        item
        for item in result.graph_edges
        if item.relationship_id == content[0].relationship_id
    ]
    assert len(edges) == 2
    assert all(
        item.direct_rule_support and not item.transitive_inference for item in edges
    )


def test_model_identity_group_is_unsupported_but_analysis_group_remains_separate() -> (
    None
):
    first = _rebuild_record(
        adapt_ml_inference(ml_source()),
        observation=adapt_ml_inference(ml_source()).observation.model_copy(
            update={"model_version": "1.0.0"}
        ),
    )
    second_base = _second_ml()
    second = _rebuild_record(
        second_base,
        observation=second_base.observation.model_copy(
            update={"model_version": "1.0.0"}
        ),
    )
    result = _correlate(first, second)
    assert any(
        item.relationship_type == "shared_analysis_context"
        for item in result.relationships
    )
    assert any(item.status == "unsupported_relation" for item in result.evaluations)


def test_origin_trust_synthetic_and_verification_are_preserved_per_record() -> None:
    static = adapt_static_analysis(static_source())
    ml = _reference(adapt_ml_inference(ml_source()), static)
    result = _correlate(static, ml)
    relationship = next(
        item
        for item in result.relationships
        if item.relationship_type == "explicit_evidence_reference"
    )
    by_id = {item.evidence_id: item for item in relationship.evidence_references}
    assert by_id[ml.identifier.evidence_id].synthetic is True
    assert by_id[static.identifier.evidence_id].synthetic is False
    assert len({item.origin_type for item in by_id.values()}) == 2
    assert (
        by_id[ml.identifier.evidence_id].trust_classification
        == ml.provenance.trust_classification
    )
    assert (
        by_id[static.identifier.evidence_id].trust_classification
        == static.provenance.trust_classification
    )


def test_deterministic_output_survives_input_permutation() -> None:
    records = (
        adapt_static_analysis(static_source()),
        _second_static(),
        adapt_vulnerability_intelligence(vulnerability_source()),
        _second_vulnerability(),
    )
    left = _correlate(*records)
    right = _correlate(*reversed(records))
    assert left.model_dump_json() == right.model_dump_json()


@pytest.mark.parametrize("version", ["0.9.0", "2.0.0", "latest"])
def test_unknown_request_schema_version_is_rejected(version: str) -> None:
    batch = create_evidence_batch((adapt_static_analysis(static_source()),))
    with pytest.raises(ValidationError):
        MultilayerCorrelationRequest.model_validate(
            {"schema_version": version, "batch": batch.model_dump()}
        )


def test_tampered_relationship_and_summary_are_rejected() -> None:
    result = _correlate(adapt_static_analysis(static_source()), _second_static())
    relationship = result.relationships[0]
    with pytest.raises(ValidationError):
        CorrelationRelationship.model_validate(
            {**relationship.model_dump(), "relationship_id": "crr_" + "0" * 64}
        )
    with pytest.raises(ValidationError):
        MultilayerCorrelationResult.model_validate(
            {
                **result.model_dump(),
                "summary": result.summary.model_copy(
                    update={"relationships": 0}
                ).model_dump(),
            }
        )


def test_layer_contracts_reject_tampering_and_orphan_graph_edges() -> None:
    result = _correlate(adapt_static_analysis(static_source()), _second_static())
    candidate = result.candidates[0]
    evaluation = result.evaluations[0]
    relationship = result.relationships[0]
    node = result.graph_nodes[0]
    edge = result.graph_edges[0]

    invalid_models = (
        (
            CorrelationCandidate,
            {
                **candidate.model_dump(),
                "evidence_ids": tuple(reversed(candidate.evidence_ids)),
            },
        ),
        (
            CorrelationCandidate,
            {**candidate.model_dump(), "candidate_id": "crc_" + "0" * 64},
        ),
        (
            CorrelationEvaluation,
            {**evaluation.model_dump(), "relationship_supported": False},
        ),
        (
            CorrelationEvaluation,
            {**evaluation.model_dump(), "evaluation_id": "cre_" + "0" * 64},
        ),
        (
            CorrelationRelationship,
            {
                **relationship.model_dump(),
                "evidence_ids": tuple(reversed(relationship.evidence_ids)),
            },
        ),
        (
            CorrelationRelationship,
            {
                **relationship.model_dump(),
                "evidence_references": tuple(
                    reversed(relationship.evidence_references)
                ),
            },
        ),
        (CorrelationGraphNode, {**node.model_dump(), "node_id": "evd_" + "0" * 64}),
        (
            CorrelationGraphEdge,
            {**edge.model_dump(), "source_node_id": edge.target_node_id},
        ),
        (
            CorrelationGraphEdge,
            {
                **edge.model_dump(),
                "evidence_references": tuple(reversed(edge.evidence_references)),
            },
        ),
        (CorrelationGraphEdge, {**edge.model_dump(), "edge_id": "crg_" + "0" * 64}),
    )
    for model, payload in invalid_models:
        with pytest.raises(ValidationError):
            model.model_validate(payload)

    orphan_relationship_id = "crr_" + "0" * 64
    edge_material = {
        "relationship_id": orphan_relationship_id,
        "rule_id": edge.rule_id,
        "relationship_type": edge.relationship_type.value,
        "source": edge.source_node_id,
        "target": edge.target_node_id,
    }
    orphan = CorrelationGraphEdge.model_validate(
        {
            **edge.model_dump(),
            "relationship_id": orphan_relationship_id,
            "edge_id": correlation_content_id("crg", edge_material),
        }
    )
    with pytest.raises(ValidationError, match="published relationships"):
        MultilayerCorrelationResult.model_validate(
            {**result.model_dump(), "graph_edges": (orphan,)}
        )


def test_correlation_conflict_identifier_is_content_verified() -> None:
    first = adapt_static_analysis(static_source())
    second = adapt_static_analysis(
        static_source().model_copy(
            update={
                "fingerprint": static_source().fingerprint.model_copy(
                    update={"sha256": "b" * 64}
                )
            }
        )
    )
    conflict = _correlate(first, second).conflicts[0]
    with pytest.raises(ValidationError):
        CorrelationConflict.model_validate(
            {**conflict.model_dump(), "conflict_id": "crf_" + "0" * 64}
        )


def test_result_rejects_nondeterministic_ordering() -> None:
    result = _correlate(
        adapt_static_analysis(static_source()),
        _second_static(),
        adapt_vulnerability_intelligence(vulnerability_source()),
        _second_vulnerability(),
    )
    with pytest.raises(ValidationError):
        MultilayerCorrelationResult.model_validate(
            {
                **result.model_dump(),
                "relationships": list(reversed(result.relationships)),
            }
        )


def test_rule_registry_is_static_versioned_and_rejects_mutation_patterns() -> None:
    assert DEFAULT_CORRELATION_RULE_REGISTRY.rules == tuple(
        sorted(BUILTIN_CORRELATION_RULES, key=lambda item: item.rule_id)
    )
    assert all(
        item.version == "1.0.0" and not item.dynamic_expression
        for item in BUILTIN_CORRELATION_RULES
    )
    with pytest.raises(CorrelationRuleRegistryError):
        CorrelationRuleRegistry((BUILTIN_CORRELATION_RULES[0],) * 2)
    with pytest.raises(CorrelationRuleRegistryError):
        CorrelationRuleRegistry(())
    with pytest.raises(CorrelationRuleRegistryError):
        DEFAULT_CORRELATION_RULE_REGISTRY.get("CR-NOPE-999")


def test_dynamic_rules_and_scores_are_contractually_forbidden() -> None:
    rule = BUILTIN_CORRELATION_RULES[0]
    for update in ({"dynamic_expression": True}, {"score_generated": True}):
        with pytest.raises(ValidationError):
            CorrelationRule.model_validate({**rule.model_dump(), **update})


def test_identity_is_recomputed_from_batch_and_no_precomputed_input_exists() -> None:
    fields = MultilayerCorrelationRequest.model_fields
    assert set(fields) == {"schema_version", "batch"}
    source = inspect.getsource(correlate_evidence)
    assert "resolve_identities" in source
    assert "IdentityResolutionRequest(batch=request.batch)" in source


def test_candidate_selection_reuses_identity_groups_without_pair_generation() -> None:
    records = (
        adapt_static_analysis(static_source()),
        _second_static(),
        adapt_static_analysis(
            static_source().model_copy(
                update={"analysis_id": UUID("80000000-0000-4000-8000-000000000008")}
            )
        ),
    )
    batch = create_evidence_batch(records)
    identity = resolve_identities(IdentityResolutionRequest(batch=batch))
    selection = select_candidates(batch, identity)
    groups = [item for item in selection.candidates if item.identity_group_id]
    assert len(groups) == 1
    assert len(groups[0].evidence_ids) == 3


def test_contract_limits_are_explicit_and_coherent() -> None:
    assert MAX_CORRELATION_CANDIDATES == MAX_CORRELATION_EVALUATIONS == 512
    assert MAX_CORRELATION_RELATIONSHIPS == 256
    assert MAX_CORRELATION_GRAPH_EDGES == 512
    assert MAX_CORRELATION_OUTPUT_BYTES == 1024 * 1024


def test_output_is_privacy_minimized_and_contains_no_raw_payload() -> None:
    result = _correlate(adapt_static_analysis(static_source()), _second_static())
    encoded = result.model_dump_json()
    assert "secret-user-path.exe" not in encoded
    assert "a" * 64 not in encoded
    assert all(
        not item.raw_content_disclosed
        for rel in result.relationships
        for item in rel.evidence_references
    )


def test_correlation_modules_have_no_io_network_persistence_or_dynamic_execution() -> (
    None
):
    import app.correlation.candidates as candidates_module
    import app.correlation.evaluation as evaluation_module
    import app.correlation.graph as graph_module
    import app.correlation.relationships as relationships_module
    import app.correlation.service as service_module

    source = "\n".join(
        inspect.getsource(module)
        for module in (
            candidates_module,
            evaluation_module,
            graph_module,
            relationships_module,
            service_module,
        )
    )
    forbidden = (
        "requests.",
        "httpx.",
        "socket.",
        "subprocess.",
        "open(",
        "eval(",
        "exec(",
        "sqlite",
        "redis",
    )
    assert not any(token in source for token in forbidden)


def test_json_round_trip_preserves_strict_result() -> None:
    result = _correlate(adapt_static_analysis(static_source()), _second_static())
    restored = MultilayerCorrelationResult.model_validate_json(result.model_dump_json())
    assert restored == result
    assert json.loads(restored.model_dump_json())["schema_version"] == "1.0.0"
