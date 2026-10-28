from __future__ import annotations

import builtins
import json
import socket
import subprocess

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import create_app
from app.multilayer.admission import admit_sources
from app.scenarios.generator import generate_synthetic_evidence
from app.scenarios.registry import (
    BUILTIN_SYNTHETIC_SCENARIOS,
    DEFAULT_SYNTHETIC_SCENARIO_REGISTRY,
    SyntheticScenarioRegistry,
    SyntheticScenarioRegistryError,
)
from app.scenarios.service import execute_synthetic_scenario
from app.schemas.multilayer_analysis import MultilayerAnalysisRequest
from app.schemas.sufficiency import SufficiencyState
from app.schemas.synthetic_scenarios import (
    MAX_SYNTHETIC_EVIDENCE,
    ScenarioValidationStatus,
    SyntheticExpectedAssessment,
    SyntheticScenarioDefinition,
    SyntheticScenarioExecutionRequest,
    SyntheticScenarioExecutionResult,
    SyntheticScenarioExpectation,
)

SCENARIO_IDS = tuple(
    item.definition.metadata.identifier.scenario_id
    for item in DEFAULT_SYNTHETIC_SCENARIO_REGISTRY.scenarios
)


def _execute(scenario_id: str) -> SyntheticScenarioExecutionResult:
    return execute_synthetic_scenario(scenario_id)


def test_registry_discovers_bounded_sorted_versioned_scenarios() -> None:
    assert len(SCENARIO_IDS) == 11
    assert SCENARIO_IDS == tuple(sorted(SCENARIO_IDS))
    assert all(
        item.registry_version == "synthetic-scenarios/1.0.0"
        and item.definition.metadata.identifier.version == "1.0.0"
        for item in DEFAULT_SYNTHETIC_SCENARIO_REGISTRY.scenarios
    )


def test_registry_rejects_unknown_scenario_and_version() -> None:
    with pytest.raises(SyntheticScenarioRegistryError, match="unknown"):
        DEFAULT_SYNTHETIC_SCENARIO_REGISTRY.get("scenario_not_registered")
    with pytest.raises(SyntheticScenarioRegistryError, match="unsupported"):
        DEFAULT_SYNTHETIC_SCENARIO_REGISTRY.get(SCENARIO_IDS[0], "2.0.0")


def test_registry_rejects_duplicate_identifiers_and_invalid_size() -> None:
    with pytest.raises(SyntheticScenarioRegistryError, match="duplicate"):
        SyntheticScenarioRegistry(
            (BUILTIN_SYNTHETIC_SCENARIOS[0], BUILTIN_SYNTHETIC_SCENARIOS[0])
        )
    with pytest.raises(SyntheticScenarioRegistryError, match="size"):
        SyntheticScenarioRegistry(())


def test_registry_mapping_and_models_are_immutable() -> None:
    with pytest.raises(TypeError):
        DEFAULT_SYNTHETIC_SCENARIO_REGISTRY.by_id[SCENARIO_IDS[0]] = (  # type: ignore[index]
            BUILTIN_SYNTHETIC_SCENARIOS[0]
        )
    with pytest.raises(ValidationError, match="frozen"):
        DEFAULT_SYNTHETIC_SCENARIO_REGISTRY.scenarios[
            0
        ].definition.metadata.title = "changed"  # type: ignore[misc]


def test_execution_request_and_definition_forbid_arbitrary_properties() -> None:
    with pytest.raises(ValidationError, match="Extra inputs"):
        SyntheticScenarioExecutionRequest.model_validate(
            {
                "scenario_id": SCENARIO_IDS[0],
                "script": "print('not allowed')",
            }
        )
    payload = BUILTIN_SYNTHETIC_SCENARIOS[0].definition.model_dump(mode="json")
    payload["runtime_rule"] = "always correlate"
    with pytest.raises(ValidationError, match="Extra inputs"):
        SyntheticScenarioDefinition.model_validate(payload)


def test_definition_rejects_oversized_sources_and_missing_references() -> None:
    definition = BUILTIN_SYNTHETIC_SCENARIOS[0].definition
    oversized = definition.model_dump(mode="json")
    oversized["sources"] = [
        {
            **definition.sources[0].model_dump(mode="json"),
            "source_id": f"fixture_oversize_{index}",
        }
        for index in range(MAX_SYNTHETIC_EVIDENCE + 1)
    ]
    with pytest.raises(ValidationError):
        SyntheticScenarioDefinition.model_validate(oversized)
    broken = definition.model_dump(mode="json")
    broken["assertions"][0]["source_ids"] = ["fixture_missing"]
    with pytest.raises(ValidationError, match="unknown source"):
        SyntheticScenarioDefinition.model_validate(broken)


@pytest.mark.parametrize("scenario_id", SCENARIO_IDS)
def test_registered_scenario_executes_and_validates(scenario_id: str) -> None:
    result = _execute(scenario_id)
    assert result.validation.status is ScenarioValidationStatus.PASSED
    assert result.validation.discrepancies == ()
    assert result.evidence.synthetic is True
    assert result.evidence.external_telemetry_authenticated is False
    assert result.persistence_performed is False
    assert result.external_io_performed is False
    assert result.dynamic_rule_execution_performed is False
    assert result.model_execution_performed is False


@pytest.mark.parametrize("scenario_id", SCENARIO_IDS)
def test_generation_is_deterministic_and_ids_are_closed(scenario_id: str) -> None:
    scenario = DEFAULT_SYNTHETIC_SCENARIO_REGISTRY.get(scenario_id)
    first, first_mapping = generate_synthetic_evidence(scenario)
    second, second_mapping = generate_synthetic_evidence(scenario)
    assert first == second
    assert first_mapping == second_mapping
    known = {item.identifier.evidence_id for item in first.records}
    assert known == set(first_mapping.values())
    assert all(
        reference.referenced_evidence_id in known
        and reference.source_evidence_id in known
        for record in first.records
        for reference in record.references
    )


@pytest.mark.parametrize("scenario_id", SCENARIO_IDS)
def test_execution_is_semantically_deterministic(scenario_id: str) -> None:
    first = _execute(scenario_id)
    second = _execute(scenario_id)
    assert first == second
    assert first.model_dump_json() == second.model_dump_json()
    assert first.execution_id.startswith("sce_")
    assert len(first.observed.assessment_ids) == len(first.observed.decision_trace_ids)


def test_generation_is_invariant_to_definition_source_order() -> None:
    scenario = DEFAULT_SYNTHETIC_SCENARIO_REGISTRY.get("scenario_shared_file_content")
    reordered_definition = scenario.definition.model_copy(
        update={"sources": tuple(reversed(scenario.definition.sources))}
    )
    reordered = scenario.model_copy(update={"definition": reordered_definition})
    original_batch, original_mapping = generate_synthetic_evidence(scenario)
    reordered_batch, reordered_mapping = generate_synthetic_evidence(reordered)
    assert original_batch == reordered_batch
    assert original_mapping == reordered_mapping


@pytest.mark.parametrize(
    ("scenario_id", "state", "relationship"),
    (
        (
            "scenario_shared_file_content",
            SufficiencyState.SUFFICIENT,
            "shared_content_identity",
        ),
        (
            "scenario_shared_vulnerability_identity",
            SufficiencyState.SUFFICIENT,
            "shared_vulnerability_identity",
        ),
        (
            "scenario_shared_analysis_context",
            SufficiencyState.SUFFICIENT,
            "shared_analysis_context",
        ),
        (
            "scenario_explicit_evidence_reference",
            SufficiencyState.SUFFICIENT,
            "explicit_evidence_reference",
        ),
    ),
)
def test_supported_scenarios_require_real_engine_relationships(
    scenario_id: str, state: SufficiencyState, relationship: str
) -> None:
    result = _execute(scenario_id)
    assert result.observed.assessment_statuses[0].status is state
    assert tuple(item.value for item in result.observed.relationship_types) == (
        relationship,
    )
    assert result.observed.relationship_ids


@pytest.mark.parametrize(
    ("scenario_id", "state"),
    (
        ("scenario_conflicting_file_identity", SufficiencyState.CONFLICTING_EVIDENCE),
        (
            "scenario_unrelated_vulnerabilities",
            SufficiencyState.INSUFFICIENT_EVIDENCE,
        ),
        (
            "scenario_cross_namespace_analysis",
            SufficiencyState.INSUFFICIENT_EVIDENCE,
        ),
        ("scenario_insufficient_cross_module", SufficiencyState.NOT_APPLICABLE),
        (
            "scenario_unsupported_threat_assertion",
            SufficiencyState.UNSUPPORTED_ASSERTION,
        ),
        (
            "scenario_empty_non_positive_correlation",
            SufficiencyState.INSUFFICIENT_EVIDENCE,
        ),
    ),
)
def test_negative_scenarios_preserve_absence_and_uncertainty(
    scenario_id: str, state: SufficiencyState
) -> None:
    result = _execute(scenario_id)
    assert result.observed.assessment_statuses[0].status is state
    assert result.observed.relationship_types == ()
    assert result.observed.relationship_ids == ()
    assert result.observed.uncertainty_categories
    assert result.observed.threat_verdict_generated is False


def test_conflict_is_retained_without_source_precedence() -> None:
    result = _execute("scenario_conflicting_file_identity")
    assert result.observed.relevant_conflicts == 1
    assert result.observed.relationship_types == ()


def test_cross_module_equal_uuid_remains_separate() -> None:
    result = _execute("scenario_cross_namespace_analysis")
    assert result.observed.relationship_types == ()
    assert "unsupported_cross_module_relation" in {
        item.value for item in result.observed.uncertainty_categories
    }


def test_mismatched_expectation_is_reported_without_correcting_actual_result() -> None:
    original = DEFAULT_SYNTHETIC_SCENARIO_REGISTRY.get("scenario_shared_file_content")
    false_expectation = SyntheticScenarioExpectation(
        assessments=(
            SyntheticExpectedAssessment(
                assertion_id="AS-CONTENT-001",
                status=SufficiencyState.INSUFFICIENT_EVIDENCE,
            ),
        ),
        positive_relationships_absent=True,
    )
    altered_definition = original.definition.model_copy(
        update={"expectation": false_expectation}
    )
    altered = original.model_copy(update={"definition": altered_definition})
    registry = SyntheticScenarioRegistry((altered,))
    result = execute_synthetic_scenario(
        "scenario_shared_file_content", registry=registry
    )
    assert result.validation.status is ScenarioValidationStatus.FAILED
    assert result.validation.discrepancies
    assert result.observed.assessment_statuses[0].status is SufficiencyState.SUFFICIENT
    assert result.observed.relationship_types[0].value == "shared_content_identity"


def test_backend_synthetic_provenance_is_preserved_on_every_record() -> None:
    for scenario in DEFAULT_SYNTHETIC_SCENARIO_REGISTRY.scenarios:
        batch, _ = generate_synthetic_evidence(scenario)
        assert all(
            item.provenance.origin_type.value == "synthetic_generated"
            and item.provenance.trust_classification.value == "internal_derivation"
            and item.provenance.synthetic
            and item.provenance.origin_verified
            for item in batch.records
        )


def test_client_declared_admission_cannot_escalate_to_synthetic_provenance() -> None:
    request = MultilayerAnalysisRequest.model_validate(
        {
            "sources": [
                {
                    "input_type": "declared_static",
                    "source_id": "src_client",
                    "analysis_context_id": "30000000-0000-4000-8000-000000000001",
                    "sha256": "f" * 64,
                    "size_bytes": 32,
                }
            ],
            "assertions": [
                {
                    "assertion_id": "AS-CONTENT-001",
                    "source_ids": ["src_client"],
                }
            ],
        }
    )
    batch, _, references = admit_sources(request)
    assert batch.records[0].provenance.origin_type.value == "client_declared"
    assert batch.records[0].provenance.synthetic is False
    assert references[0].synthetic is False
    forged = request.model_dump(mode="json")
    forged["sources"][0]["synthetic_generated"] = True
    with pytest.raises(ValidationError, match="Extra inputs"):
        MultilayerAnalysisRequest.model_validate(forged)


def test_no_arbitrary_batch_or_seed_is_accepted_by_execution_interface() -> None:
    with pytest.raises(TypeError):
        execute_synthetic_scenario(  # type: ignore[call-arg]
            SCENARIO_IDS[0], evidence_batch={}
        )
    with pytest.raises(TypeError):
        execute_synthetic_scenario(SCENARIO_IDS[0], seed=123)  # type: ignore[call-arg]


def test_execution_performs_no_filesystem_network_or_subprocess_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_: object, **__: object) -> None:
        raise AssertionError("external effect attempted")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    result = _execute("scenario_synthetic_provenance")
    assert result.validation.status is ScenarioValidationStatus.PASSED


def test_outputs_contain_no_privacy_canaries_or_operational_claims() -> None:
    forbidden = (
        "password",
        "secret=",
        "c:\\users\\",
        "@example.com",
        "host compromise",
        "attack confirmed",
        "malware detected",
    )
    for scenario_id in SCENARIO_IDS:
        payload = _execute(scenario_id).model_dump_json().lower()
        assert all(canary not in payload for canary in forbidden)


def test_output_is_bounded_and_uses_compact_references() -> None:
    for scenario_id in SCENARIO_IDS:
        result = _execute(scenario_id)
        encoded = result.model_dump_json().encode()
        assert len(encoded) < 512 * 1024
        assert len(result.evidence.evidence_ids) <= MAX_SYNTHETIC_EVIDENCE
        assert len(result.observed.decision_trace_ids) <= 32


def test_http_surface_stays_at_35_operations_and_scenarios_are_not_admitted() -> None:
    app = create_app()
    client = TestClient(app)
    schema = client.get("/openapi.json").json()
    operations = sum(
        method.lower() in {"get", "post", "put", "patch", "delete"}
        for methods in schema["paths"].values()
        for method in methods
    )
    assert operations == 35
    assert "/api/v1/multilayer/scenarios" not in schema["paths"]
    assert client.get("/api/v1/multilayer/scenarios").status_code == 404


def test_schema_contract_has_no_executable_or_arbitrary_payload_fields() -> None:
    schema = SyntheticScenarioDefinition.model_json_schema()
    encoded = json.dumps(schema, sort_keys=True).lower()
    assert "script" not in encoded
    assert "expression" not in encoded
    assert "evidencebatch" not in encoded
    assert "callable" not in encoded
