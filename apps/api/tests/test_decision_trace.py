from __future__ import annotations

import inspect

import pytest
from pydantic import ValidationError

from app.evidence.adapters import (
    adapt_ml_inference,
    adapt_static_analysis,
    adapt_vulnerability_intelligence,
    create_evidence_batch,
)
from app.explainability import explain_decisions
from app.schemas.explainability import (
    MAX_TRACE_DEPTH,
    MAX_TRACE_EDGES,
    MAX_TRACE_NODES,
    MAX_TRACES_PER_REQUEST,
    DecisionTrace,
    DecisionTraceRequest,
    DecisionTraceResult,
    ExplanationStatement,
    ExplanationTemplateId,
    TraceEdge,
    TraceEdgeType,
    TraceNode,
    TraceNodeState,
    TraceNodeType,
    trace_content_id,
)
from app.schemas.sufficiency import AssertionSelection, SufficiencyState
from tests.test_identity_resolution import _second_static, _second_vulnerability
from tests.test_multilayer_correlation import _reference, _second_ml
from tests.test_unified_evidence import (
    ml_source,
    static_source,
    vulnerability_source,
)


def _result(
    assertion_id: str, *records: object, evidence_ids: tuple[str, ...] | None = None
) -> DecisionTraceResult:
    batch = create_evidence_batch(tuple(records))  # type: ignore[arg-type]
    selected = (
        tuple(item.identifier.evidence_id for item in batch.records)
        if evidence_ids is None
        else tuple(sorted(evidence_ids))
    )
    return explain_decisions(
        DecisionTraceRequest(
            batch=batch,
            assertions=(
                AssertionSelection(assertion_id=assertion_id, evidence_ids=selected),
            ),
        )
    )


def _trace(
    assertion_id: str, *records: object, evidence_ids: tuple[str, ...] | None = None
) -> DecisionTrace:
    return _result(assertion_id, *records, evidence_ids=evidence_ids).traces[0]


@pytest.mark.parametrize(
    ("assertion_id", "records", "identity_rule", "correlation_rule"),
    [
        (
            "AS-CONTENT-001",
            (adapt_static_analysis(static_source()), _second_static()),
            "IR-FILE-001",
            "CR-CONTENT-001",
        ),
        (
            "AS-VULN-001",
            (
                adapt_vulnerability_intelligence(vulnerability_source()),
                _second_vulnerability(),
            ),
            "IR-CVE-001",
            "CR-VULN-001",
        ),
        (
            "AS-ANALYSIS-001",
            (adapt_ml_inference(ml_source()), _second_ml()),
            "IR-ANALYSIS-001",
            "CR-ANALYSIS-001",
        ),
    ],
)
def test_sufficient_trace_reconstructs_exact_identity_and_correlation(
    assertion_id: str,
    records: tuple[object, ...],
    identity_rule: str,
    correlation_rule: str,
) -> None:
    trace = _trace(assertion_id, *records)
    assert trace.decision_status is SufficiencyState.SUFFICIENT
    assert trace.policy_reference is not None
    assert trace.policy_reference.assertion_id == assertion_id
    assert {item.rule_id for item in trace.identity_references} == {identity_rule}
    assert {item.rule_id for item in trace.correlation_references} == {correlation_rule}
    assert trace.summary.requirements_complete is True
    assert trace.summary.satisfied_requirements == trace.summary.requirements
    assert trace.decision_changed is False
    assert trace.causal_explanation is False


def test_explicit_reference_trace_explains_only_validated_link() -> None:
    static = adapt_static_analysis(static_source())
    ml = _reference(adapt_ml_inference(ml_source()), static)
    trace = _trace("AS-REF-001", static, ml)
    assert trace.decision_status == "sufficient"
    assert not trace.identity_references
    assert {item.rule_id for item in trace.correlation_references} == {"CR-REF-001"}
    assert any("causality" in item.statement for item in trace.limitations)


def test_insufficient_trace_keeps_every_missing_requirement_visible() -> None:
    trace = _trace(
        "AS-CONTENT-001",
        adapt_static_analysis(static_source()),
        _second_static(sha256="b" * 64),
    )
    assert trace.decision_status == "insufficient_evidence"
    missing = [item for item in trace.requirement_references if item.state == "missing"]
    assert {item.requirement_id for item in missing} == {
        "required_identity_satisfied",
        "required_correlation_supported",
    }
    explained = {item.source_reference_id for item in trace.explanation_statements}
    assert {item.requirement_evaluation_id for item in missing}.issubset(explained)
    assert trace.summary.requirements == 5


def test_conflicting_trace_preserves_relevant_contradiction() -> None:
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
    trace = _trace("AS-CONTENT-001", first, second)
    assert trace.decision_status == "conflicting_evidence"
    assert trace.contradiction_references
    assert all(
        not item.source_precedence_applied for item in trace.contradiction_references
    )
    assert any(item.edge_type == "conflicts_with" for item in trace.edges)


def test_irrelevant_contradiction_is_excluded_from_cve_trace() -> None:
    first_static = adapt_static_analysis(static_source())
    second_static = adapt_static_analysis(
        static_source().model_copy(
            update={
                "fingerprint": static_source().fingerprint.model_copy(
                    update={"sha256": "b" * 64}
                )
            }
        )
    )
    first_cve = adapt_vulnerability_intelligence(vulnerability_source())
    second_cve = _second_vulnerability()
    selected = tuple(
        sorted((first_cve.identifier.evidence_id, second_cve.identifier.evidence_id))
    )
    trace = _trace(
        "AS-VULN-001",
        first_static,
        second_static,
        first_cve,
        second_cve,
        evidence_ids=selected,
    )
    assert trace.decision_status == "sufficient"
    assert not trace.contradiction_references
    assert {item.evidence_id for item in trace.evidence_references} == set(selected)


def test_not_applicable_trace_explains_all_requirement_outcomes() -> None:
    trace = _trace(
        "AS-CONTENT-001",
        adapt_vulnerability_intelligence(vulnerability_source()),
        _second_vulnerability(),
    )
    assert trace.decision_status == "not_applicable"
    assert trace.summary.not_applicable_requirements > 0
    assert len(trace.requirement_references) == 5


@pytest.mark.parametrize(
    "assertion_id",
    [
        "AS-EXPLOIT-001",
        "AS-ATTACK-001",
        "AS-MALWARE-001",
        "AS-EXECUTION-001",
        "AS-COMPROMISE-001",
        "AS-PERSISTENCE-001",
        "AS-CONTROL-001",
        "AS-ATTRIBUTION-001",
        "AS-SEQUENCE-001",
        "AS-MLVALID-001",
    ],
)
def test_negative_explanation_matrix_stays_unsupported(assertion_id: str) -> None:
    trace = _trace(assertion_id, adapt_ml_inference(ml_source()))
    assert trace.decision_status == "unsupported_assertion"
    assert trace.policy_reference is None
    assert not trace.requirement_references
    assert not trace.identity_references
    assert trace.threat_confirmed is False
    statement = next(
        item
        for item in trace.explanation_statements
        if item.source_reference_id == trace.identifier.source_assessment_id
    )
    assert statement.template_id is ExplanationTemplateId.DECISION_UNSUPPORTED


def test_synthetic_provenance_and_missing_model_version_remain_explicit() -> None:
    trace = _trace("AS-ANALYSIS-001", adapt_ml_inference(ml_source()), _second_ml())
    assert all(item.synthetic for item in trace.evidence_references)
    categories = {item.category for item in trace.uncertainty_references}
    assert "synthetic_origin" in categories
    assert "missing_model_version" in categories
    assert trace.decision_status == "sufficient"


def test_source_phase_origin_and_verification_are_preserved() -> None:
    trace = _trace(
        "AS-VULN-001",
        adapt_vulnerability_intelligence(vulnerability_source()),
        _second_vulnerability(),
    )
    assert {item.source_phase for item in trace.evidence_references} == {"04"}
    assert all(not item.origin_verified for item in trace.evidence_references)
    assert {item.origin_type for item in trace.evidence_references} == {
        "external_intelligence"
    }


def test_graph_contains_only_direct_existing_dependencies() -> None:
    trace = _trace(
        "AS-CONTENT-001",
        adapt_static_analysis(static_source()),
        _second_static(),
    )
    node_ids = {item.node_id for item in trace.nodes}
    assert all(
        item.source_node_id in node_ids and item.target_node_id in node_ids
        for item in trace.edges
    )
    assert all(
        item.direct_dependency and not item.transitive_inference for item in trace.edges
    )
    assert trace.summary.maximum_depth <= 2
    assert any(item.edge_type == "depends_on_identity" for item in trace.edges)
    assert any(item.edge_type == "depends_on_correlation" for item in trace.edges)


def test_static_templates_are_exact_versioned_and_non_llm() -> None:
    trace = _trace(
        "AS-CONTENT-001",
        adapt_static_analysis(static_source()),
        _second_static(),
    )
    assert all(
        item.template_version == "1.0.0" for item in trace.explanation_statements
    )
    assert all(not item.generated_by_llm for item in trace.explanation_statements)
    statement = trace.explanation_statements[0]
    with pytest.raises(ValidationError, match="static template"):
        ExplanationStatement.model_validate(
            {**statement.model_dump(), "message": "User-controlled explanation"}
        )


def test_trace_node_edge_and_trace_ids_reject_manipulation() -> None:
    trace = _trace(
        "AS-CONTENT-001",
        adapt_static_analysis(static_source()),
        _second_static(),
    )
    with pytest.raises(ValidationError):
        TraceNode.model_validate(
            {**trace.nodes[0].model_dump(), "node_id": "trn_" + "0" * 64}
        )
    with pytest.raises(ValidationError):
        TraceEdge.model_validate(
            {**trace.edges[0].model_dump(), "edge_id": "tre_" + "0" * 64}
        )
    with pytest.raises(ValidationError):
        DecisionTrace.model_validate(
            {
                **trace.model_dump(),
                "identifier": {
                    **trace.identifier.model_dump(),
                    "trace_id": "dtr_" + "0" * 64,
                },
            }
        )


def test_orphan_edge_and_missing_reference_node_are_rejected() -> None:
    trace = _trace(
        "AS-CONTENT-001",
        adapt_static_analysis(static_source()),
        _second_static(),
    )
    edge = trace.edges[0]
    missing_node_id = "trn_" + "0" * 64
    material = {
        "edge_type": edge.edge_type.value,
        "source": edge.source_node_id,
        "target": missing_node_id,
    }
    orphan = TraceEdge(
        edge_id=trace_content_id("tre", material),
        edge_type=edge.edge_type,
        source_node_id=edge.source_node_id,
        target_node_id=missing_node_id,
    )
    with pytest.raises(ValidationError, match="existing nodes"):
        DecisionTrace.model_validate(
            {
                **trace.model_dump(),
                "edges": tuple(sorted((*trace.edges, orphan), key=lambda x: x.edge_id)),
            }
        )
    evidence_object = trace.evidence_references[0].evidence_id
    without_evidence_node = tuple(
        item for item in trace.nodes if item.object_id != evidence_object
    )
    with pytest.raises(ValidationError):
        DecisionTrace.model_validate(
            {**trace.model_dump(), "nodes": without_evidence_node}
        )


def test_duplicate_nodes_edges_and_statements_are_rejected() -> None:
    trace = _trace(
        "AS-CONTENT-001",
        adapt_static_analysis(static_source()),
        _second_static(),
    )
    mutations = (
        {
            "nodes": tuple(
                sorted((*trace.nodes, trace.nodes[0]), key=lambda x: x.node_id)
            )
        },
        {
            "edges": tuple(
                sorted((*trace.edges, trace.edges[0]), key=lambda x: x.edge_id)
            )
        },
        {
            "explanation_statements": tuple(
                sorted(
                    (*trace.explanation_statements, trace.explanation_statements[0]),
                    key=lambda x: x.statement_id,
                )
            )
        },
    )
    for mutation in mutations:
        with pytest.raises(ValidationError, match="unique"):
            DecisionTrace.model_validate({**trace.model_dump(), **mutation})


def test_cyclic_dependency_and_excessive_depth_are_rejected() -> None:
    trace = _trace(
        "AS-CONTENT-001",
        adapt_static_analysis(static_source()),
        _second_static(),
    )
    root = next(item for item in trace.nodes if item.node_type == "assertion")
    evidence = next(item for item in trace.nodes if item.node_type == "evidence")
    cycle_material = {
        "edge_type": TraceEdgeType.USES_EVIDENCE.value,
        "source": evidence.node_id,
        "target": root.node_id,
    }
    cycle = TraceEdge(
        edge_id=trace_content_id("tre", cycle_material),
        edge_type=TraceEdgeType.USES_EVIDENCE,
        source_node_id=evidence.node_id,
        target_node_id=root.node_id,
    )
    with pytest.raises(ValidationError, match="acyclic"):
        DecisionTrace.model_validate(
            {
                **trace.model_dump(),
                "edges": tuple(sorted((*trace.edges, cycle), key=lambda x: x.edge_id)),
            }
        )

    extra_nodes = []
    extra_edges = []
    source = root
    for index in range(MAX_TRACE_DEPTH + 1):
        object_id = f"depth:{index:03d}"
        node_material = {
            "node_type": TraceNodeType.LIMITATION.value,
            "object_id": object_id,
            "state": TraceNodeState.RETAINED.value,
        }
        node = TraceNode(
            node_id=trace_content_id("trn", node_material),
            node_type=TraceNodeType.LIMITATION,
            object_id=object_id,
            state=TraceNodeState.RETAINED,
        )
        edge_material = {
            "edge_type": TraceEdgeType.LIMITED_BY.value,
            "source": source.node_id,
            "target": node.node_id,
        }
        extra_edges.append(
            TraceEdge(
                edge_id=trace_content_id("tre", edge_material),
                edge_type=TraceEdgeType.LIMITED_BY,
                source_node_id=source.node_id,
                target_node_id=node.node_id,
            )
        )
        extra_nodes.append(node)
        source = node
    with pytest.raises(ValidationError, match="depth"):
        DecisionTrace.model_validate(
            {
                **trace.model_dump(),
                "nodes": tuple(
                    sorted((*trace.nodes, *extra_nodes), key=lambda x: x.node_id)
                ),
                "edges": tuple(
                    sorted((*trace.edges, *extra_edges), key=lambda x: x.edge_id)
                ),
            }
        )


def test_incomplete_explanation_and_mismatched_status_are_rejected() -> None:
    trace = _trace(
        "AS-CONTENT-001",
        adapt_static_analysis(static_source()),
        _second_static(),
    )
    requirement_id = trace.requirement_references[0].requirement_evaluation_id
    incomplete = tuple(
        item
        for item in trace.explanation_statements
        if item.source_reference_id != requirement_id
    )
    with pytest.raises(ValidationError, match="incomplete"):
        DecisionTrace.model_validate(
            {**trace.model_dump(), "explanation_statements": incomplete}
        )
    with pytest.raises(ValidationError):
        DecisionTrace.model_validate(
            {**trace.model_dump(), "decision_status": "insufficient_evidence"}
        )


def test_mismatched_versions_and_untrusted_precomputed_trace_are_rejected() -> None:
    trace = _trace(
        "AS-CONTENT-001",
        adapt_static_analysis(static_source()),
        _second_static(),
    )
    with pytest.raises(ValidationError):
        type(trace.identity_references[0]).model_validate(
            {**trace.identity_references[0].model_dump(), "rule_version": "2.0.0"}
        )
    assert set(DecisionTraceRequest.model_fields) == {
        "schema_version",
        "batch",
        "assertions",
    }
    batch = create_evidence_batch((adapt_static_analysis(static_source()),))
    with pytest.raises(ValidationError):
        DecisionTraceRequest.model_validate(
            {
                "batch": batch.model_dump(),
                "assertions": [
                    {
                        "assertion_id": "AS-CONTENT-001",
                        "evidence_ids": [batch.records[0].identifier.evidence_id],
                    }
                ],
                "trusted": True,
                "trace": trace.model_dump(),
            }
        )


def test_input_permutation_and_serialization_are_deterministic() -> None:
    records = (adapt_static_analysis(static_source()), _second_static())
    left = _result("AS-CONTENT-001", *records)
    right = _result("AS-CONTENT-001", *reversed(records))
    assert left.model_dump_json() == right.model_dump_json()
    assert DecisionTraceResult.model_validate_json(left.model_dump_json()) == left


def test_assertion_order_permutation_is_deterministic() -> None:
    batch = create_evidence_batch(
        (adapt_static_analysis(static_source()), _second_static())
    )
    ids = tuple(item.identifier.evidence_id for item in batch.records)
    selections = (
        AssertionSelection(assertion_id="AS-CONTENT-001", evidence_ids=ids),
        AssertionSelection(assertion_id="AS-EXECUTION-001", evidence_ids=ids),
    )
    left = explain_decisions(DecisionTraceRequest(batch=batch, assertions=selections))
    right = explain_decisions(
        DecisionTraceRequest(batch=batch, assertions=tuple(reversed(selections)))
    )
    assert left.model_dump_json() == right.model_dump_json()


def test_resource_limits_reject_excessive_traces_nodes_and_edges() -> None:
    record = adapt_static_analysis(static_source())
    batch = create_evidence_batch((record,))
    selections = tuple(
        AssertionSelection(
            assertion_id=f"AS-TRACE-{index:03d}",
            evidence_ids=(record.identifier.evidence_id,),
        )
        for index in range(MAX_TRACES_PER_REQUEST + 1)
    )
    with pytest.raises(ValidationError):
        DecisionTraceRequest(batch=batch, assertions=selections)
    trace = _trace("AS-CONTENT-001", record)
    with pytest.raises(ValidationError):
        DecisionTrace.model_validate(
            {**trace.model_dump(), "nodes": (trace.nodes[0],) * (MAX_TRACE_NODES + 1)}
        )
    with pytest.raises(ValidationError):
        DecisionTrace.model_validate(
            {**trace.model_dump(), "edges": (trace.edges[0],) * (MAX_TRACE_EDGES + 1)}
        )


def test_privacy_canaries_absent_from_complete_trace() -> None:
    result = _result(
        "AS-CONTENT-001",
        adapt_static_analysis(static_source()),
        _second_static(),
    )
    encoded = result.model_dump_json()
    assert "secret-user-path.exe" not in encoded
    assert "a" * 64 not in encoded
    assert "command_line" not in encoded
    assert all(
        not item.raw_content_disclosed for item in result.traces[0].evidence_references
    )


def test_internal_orchestration_reuses_results_without_external_effects() -> None:
    import app.explainability.graph as graph_module
    import app.explainability.lineage as lineage_module
    import app.explainability.service as service_module
    import app.explainability.templates as templates_module

    service_source = inspect.getsource(service_module)
    assert service_source.count("resolve_identities(") == 1
    assert "correlate_evidence_with_identity" in service_source
    assert "assess_evidence_sufficiency_with_context" in service_source
    source = "\n".join(
        inspect.getsource(module)
        for module in (
            graph_module,
            lineage_module,
            service_module,
            templates_module,
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
        "predict(",
        "completion",
        "plugin",
        "random.",
    )
    assert not any(token in source for token in forbidden)


def test_result_hard_safety_flags_and_output_bound() -> None:
    result = _result(
        "AS-CONTENT-001",
        adapt_static_analysis(static_source()),
        _second_static(),
    )
    assert result.persistence_performed is False
    assert result.causal_inference_performed is False
    assert result.threat_verdict_generated is False
    assert result.scoring_performed is False
    assert result.response_action_performed is False
    assert len(result.model_dump_json()) < 1024 * 1024
