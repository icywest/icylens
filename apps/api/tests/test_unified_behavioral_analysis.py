from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from socket import socket
from threading import Event
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

import app.services.behavior_analysis as analysis_module
from app.attack.catalog import ATTACKCatalogStore
from app.behavior.correlation import TemporalCorrelationEngine
from app.behavior.rule_engine import BehavioralRuleEngine
from app.schemas.behavior import (
    EventBatch,
    EventNature,
    EventPlatform,
    EventProvenance,
    EventSource,
    EventSourceKind,
    FileAction,
    FileEvent,
    NetworkAction,
    NetworkEvent,
    NetworkProtocol,
    ProcessAction,
    ProcessEvent,
    ProcessIdentity,
    SyntheticScenarioKind,
    SyntheticScenarioRequest,
)
from app.schemas.behavior_analysis import (
    BehavioralAnalysisOptions,
    BehavioralAnalysisRequest,
    BehavioralAnalysisSource,
    BehavioralAnalysisStageName,
    BehavioralAnalysisStageStatus,
    BehavioralAnalysisStatus,
    SyntheticAnalysisRequest,
)
from app.services.attack_mapping import AttackMappingService
from app.services.behavior_analysis import (
    BehavioralAnalysisCapacity,
    BehavioralAnalysisCapacityError,
    BehavioralAnalysisLimitError,
    BehavioralAnalysisService,
    execute_behavioral_analysis,
)

NOW = datetime(2026, 10, 26, 16, 0, tzinfo=timezone.utc)
PROCESS_ID = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")


def event_id(index: int) -> UUID:
    return UUID(f"20000000-0000-4000-8000-{index:012d}")


def process_identity() -> ProcessIdentity:
    return ProcessIdentity(process_instance_id=PROCESS_ID, pid=4242, started_at=NOW)


def common(
    index: int, seconds: int = 0, *, host: str = "sensitive-host"
) -> dict[str, object]:
    timestamp = NOW + timedelta(seconds=seconds)
    source = EventSource(
        kind=EventSourceKind.DECLARED_API,
        source_id="unified-test-source",
        producer="offline fixture",
    )
    return {
        "event_id": event_id(index),
        "timestamp": timestamp,
        "host_id": host,
        "source": source,
        "platform": EventPlatform.LINUX,
        "synthetic": False,
        "provenance": EventProvenance(
            source_identifier=source.source_id,
            observed_at=timestamp,
            received_at=timestamp + timedelta(milliseconds=10),
            nature=EventNature.DECLARED,
            missing_fields=(),
            limitations=("Offline fixture.",),
        ),
        "attributes": {},
    }


def process_event(
    index: int,
    action: ProcessAction = ProcessAction.START,
    *,
    host: str = "sensitive-host",
) -> ProcessEvent:
    return ProcessEvent(
        event_type="process",
        action=action,
        process=process_identity(),
        parent_process=None,
        executable_path="/private/secret-tool",
        command_line="/private/secret-tool --password secret",
        user_context="secret-user",
        exit_code=0 if action is ProcessAction.TERMINATE else None,
        **common(index, index, host=host),
    )


def file_event(index: int, action: FileAction, seconds: int) -> FileEvent:
    return FileEvent(
        event_type="file",
        action=action,
        file_path="/private/secret.txt",
        process=process_identity(),
        **common(index, seconds),
    )


def network_event(index: int, action: NetworkAction, seconds: int) -> NetworkEvent:
    return NetworkEvent(
        event_type="network",
        action=action,
        local_ip="192.0.2.50",
        local_port=50000,
        remote_ip="198.51.100.50",
        remote_port=443,
        protocol=NetworkProtocol.TCP,
        process=process_identity(),
        **common(index, seconds),
    )


def loaded_store() -> ATTACKCatalogStore:
    store = ATTACKCatalogStore()
    store.load()
    return store


def options(
    *, rule_ids: tuple[str, ...] | None = None, policies: tuple[str, ...] | None = None
) -> BehavioralAnalysisOptions:
    return BehavioralAnalysisOptions(rule_ids=rule_ids, mapping_policy_ids=policies)


def analyze(
    events: tuple[ProcessEvent | FileEvent | NetworkEvent, ...],
    *,
    analysis_options: BehavioralAnalysisOptions | None = None,
    service: BehavioralAnalysisService | None = None,
):
    request = BehavioralAnalysisRequest(
        batch=EventBatch(events=events),
        options=analysis_options or options(),
    )
    return (service or BehavioralAnalysisService(loaded_store())).analyze(request)


def stage(result: object, name: BehavioralAnalysisStageName):
    return next(item for item in result.stages if item.stage is name)  # type: ignore[attr-defined]


@pytest.mark.unit
def test_valid_batch_runs_complete_pipeline_without_security_verdict() -> None:
    result = analyze(
        (
            process_event(1),
            process_event(2, ProcessAction.TERMINATE),
        )
    )
    assert result.status is BehavioralAnalysisStatus.COMPLETE
    assert result.source is BehavioralAnalysisSource.DECLARED_BATCH
    assert result.summary.valid_events == 2
    assert result.summary.evaluated_rules == 12
    assert result.summary.mapping_candidates == 0
    assert result.catalog_version == "19.2"
    assert all(
        item.status is BehavioralAnalysisStageStatus.COMPLETED for item in result.stages
    )
    assert result.attack_confirmed is False
    assert result.malware_detected is False
    assert result.causal_inference_performed is False
    assert result.persisted is False


@pytest.mark.unit
def test_unified_analysis_is_deterministic() -> None:
    events = (process_event(1), process_event(2, ProcessAction.TERMINATE))
    first = analyze(events)
    second = analyze(events)
    assert first == second
    assert first.analysis_id == second.analysis_id
    assert first.generated_at == second.generated_at


@pytest.mark.unit
def test_rule_selection_preserves_mapping_dependency_without_duplicate_run() -> None:
    result = analyze(
        (process_event(1),),
        analysis_options=options(rule_ids=("BR-FILE-001",), policies=("AMP-PROC-001",)),
    )
    assert [item.rule_id for item in result.rule_findings] == [
        "BR-FILE-001",
        "BR-PROC-003",
    ]
    proc = next(item for item in result.rule_findings if item.rule_id == "BR-PROC-003")
    assert proc.result.value == "matched"
    assert result.attack_mapping_evaluations[0].state.value == "insufficient_evidence"


@pytest.mark.unit
def test_rule_not_matched_and_not_applicable_remain_distinct() -> None:
    declared_http = network_event(1, NetworkAction.ATTEMPTED, 0).model_copy(
        update={"remote_port": 80}
    )
    result = analyze(
        (declared_http,),
        analysis_options=options(
            rule_ids=("BR-NET-003", "BR-FILE-001"),
            policies=("AMP-NET-001",),
        ),
    )
    states = {item.rule_id: item.result.value for item in result.rule_findings}
    assert states == {
        "BR-FILE-001": "not_applicable",
        "BR-NET-003": "not_matched",
    }
    assert result.attack_mapping_evaluations[0].state.value == "not_supported"


@pytest.mark.unit
def test_file_and_network_relationship_strength_is_preserved() -> None:
    file_result = analyze(
        (file_event(1, FileAction.CREATE, 0), file_event(2, FileAction.MODIFY, 1))
    )
    file_edges = [
        item
        for item in file_result.temporal_relationships
        if item.relationship_type.value == "same_declared_file"
    ]
    assert file_edges and all(item.confidence.value == "weak" for item in file_edges)

    network_result = analyze(
        (
            network_event(3, NetworkAction.ATTEMPTED, 0),
            network_event(4, NetworkAction.ESTABLISHED, 1),
        )
    )
    connection_edges = [
        item
        for item in network_result.temporal_relationships
        if item.relationship_type.value == "same_declared_connection"
    ]
    assert connection_edges and all(
        item.confidence.value == "weak" for item in connection_edges
    )
    assert network_result.summary.mapping_candidates == 0


@pytest.mark.unit
def test_semantically_invalid_batch_returns_explicit_partial_and_skips_engines() -> (
    None
):
    event = process_event(1)
    result = analyze((event, event))
    assert result.status is BehavioralAnalysisStatus.PARTIAL
    assert result.validation.valid is False
    assert result.summary.valid_events == 0
    assert (
        stage(result, BehavioralAnalysisStageName.VALIDATION).status
        is BehavioralAnalysisStageStatus.COMPLETED
    )
    for name in (
        BehavioralAnalysisStageName.RULES,
        BehavioralAnalysisStageName.TEMPORAL_CORRELATION,
        BehavioralAnalysisStageName.ATTACK_MAPPING,
    ):
        assert stage(result, name).status is BehavioralAnalysisStageStatus.SKIPPED
    assert result.rule_findings == ()
    assert result.temporal_relationships == ()
    assert result.attack_mapping_evaluations == ()


@pytest.mark.unit
def test_catalog_unavailable_is_partial_not_zero_techniques() -> None:
    store = ATTACKCatalogStore(Path("missing-catalog"))
    result = analyze((process_event(1),), service=BehavioralAnalysisService(store))
    assert result.status is BehavioralAnalysisStatus.PARTIAL
    mapping_stage = stage(result, BehavioralAnalysisStageName.ATTACK_MAPPING)
    assert mapping_stage.status is BehavioralAnalysisStageStatus.UNAVAILABLE
    assert result.catalog_version is None
    assert all(
        item.state.value == "catalog_unavailable"
        for item in result.attack_mapping_evaluations
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    "kind",
    [
        SyntheticScenarioKind.NORMAL_PROCESS,
        SyntheticScenarioKind.FILE_SEQUENCE,
        SyntheticScenarioKind.NETWORK_SEQUENCE,
        SyntheticScenarioKind.CONFIGURATION_CHANGE,
        SyntheticScenarioKind.INCOMPLETE_SEQUENCE,
        SyntheticScenarioKind.CONTRADICTORY_DATA,
        SyntheticScenarioKind.OUT_OF_ORDER,
    ],
)
def test_supported_synthetic_demonstrations(kind: SyntheticScenarioKind) -> None:
    count = 2
    request = SyntheticAnalysisRequest(
        scenario=SyntheticScenarioRequest(
            scenario_id=f"demo-{kind.value}",
            scenario_kind=kind,
            seed=17,
            platform=EventPlatform.WINDOWS,
            start_time=NOW,
            event_count=count,
        ),
        options=options(),
    )
    result = BehavioralAnalysisService(loaded_store()).analyze_synthetic(request)
    assert result.source is BehavioralAnalysisSource.SYNTHETIC_SCENARIO
    assert result.provenance.scenario_kind is kind
    assert result.provenance.scenario_seed == 17
    assert result.event_summary.synthetic_events == count
    assert result.provenance.events_returned is False
    assert result.attack_confirmed is False


@pytest.mark.unit
def test_synthetic_analysis_is_seed_deterministic() -> None:
    request = SyntheticAnalysisRequest(
        scenario=SyntheticScenarioRequest(
            scenario_id="deterministic-demo",
            scenario_kind=SyntheticScenarioKind.NORMAL_PROCESS,
            seed=99,
            platform=EventPlatform.LINUX,
            start_time=NOW,
            event_count=4,
        ),
        options=options(),
    )
    service = BehavioralAnalysisService(loaded_store())
    assert service.analyze_synthetic(request) == service.analyze_synthetic(request)


@pytest.mark.unit
def test_engines_execute_once_and_mapping_reuses_trusted_results() -> None:
    class CountingRules(BehavioralRuleEngine):
        calls = 0

        def evaluate(self, *args: object, **kwargs: object):
            self.calls += 1
            return super().evaluate(*args, **kwargs)  # type: ignore[arg-type]

    class CountingTemporal(TemporalCorrelationEngine):
        calls = 0

        def correlate(self, *args: object, **kwargs: object):
            self.calls += 1
            return super().correlate(*args, **kwargs)  # type: ignore[arg-type]

    class CountingMapping(AttackMappingService):
        direct_calls = 0
        trusted_calls = 0

        def evaluate(self, *args: object, **kwargs: object):
            self.direct_calls += 1
            return super().evaluate(*args, **kwargs)  # type: ignore[arg-type]

        def evaluate_trusted(self, *args: object, **kwargs: object):
            self.trusted_calls += 1
            return super().evaluate_trusted(*args, **kwargs)  # type: ignore[arg-type]

    store = loaded_store()
    rules = CountingRules()
    temporal = CountingTemporal()
    mapping = CountingMapping(store)
    service = BehavioralAnalysisService(
        store, rule_engine=rules, temporal_engine=temporal, mapping_service=mapping
    )
    analyze((process_event(1),), service=service)
    assert rules.calls == 1
    assert temporal.calls == 1
    assert mapping.trusted_calls == 1
    assert mapping.direct_calls == 0


@pytest.mark.unit
def test_sensitive_event_values_are_not_returned() -> None:
    result = analyze((process_event(1),))
    serialized = result.model_dump_json()
    assert "secret-tool" not in serialized
    assert "password" not in serialized
    assert "secret-user" not in serialized
    assert "sensitive-host" not in serialized
    assert '"events"' not in serialized
    assert all(item.raw_evidence_returned is False for item in result.rule_findings)


@pytest.mark.unit
def test_contract_rejects_client_evidence_code_and_duplicate_options() -> None:
    event = process_event(1)
    batch = {"events": [event.model_dump(mode="json")]}
    for extra in (
        {"findings": []},
        {"graph": {}},
        {"attack_ids": ["T1059"]},
        {"url": "https://example.invalid"},
        {"plugin": "arbitrary"},
        {"expression": "eval('x')"},
        {"validated": True},
    ):
        with pytest.raises(ValidationError):
            BehavioralAnalysisRequest.model_validate({"batch": batch} | extra)
    with pytest.raises(ValidationError, match="duplicates"):
        BehavioralAnalysisOptions(
            rule_ids=("BR-PROC-001", "BR-PROC-001"),
            mapping_policy_ids=None,
        )


@pytest.mark.unit
def test_deadline_and_output_limit_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    moments = iter((0.0, 4.0))
    service = BehavioralAnalysisService(loaded_store(), clock=lambda: next(moments))
    with pytest.raises(BehavioralAnalysisLimitError, match="deadline"):
        analyze((process_event(1),), service=service)

    monkeypatch.setattr(analysis_module, "MAX_UNIFIED_ANALYSIS_OUTPUT_BYTES", 10)
    with pytest.raises(BehavioralAnalysisLimitError, match="output"):
        analyze((process_event(1),))


@pytest.mark.anyio
async def test_capacity_timeout_and_cancellation_keep_real_worker_admitted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capacity = BehavioralAnalysisCapacity(1)
    assert await capacity.try_acquire() is True
    with pytest.raises(BehavioralAnalysisCapacityError):
        await execute_behavioral_analysis(lambda: None, capacity)  # type: ignore[arg-type]
    await capacity.release()

    monkeypatch.setattr(
        analysis_module, "UNIFIED_ANALYSIS_OPERATION_TIMEOUT_SECONDS", 0.001
    )
    with pytest.raises(BehavioralAnalysisLimitError, match="timed out"):
        await execute_behavioral_analysis(lambda: time.sleep(0.05), capacity)  # type: ignore[arg-type]
    assert capacity.active == 1
    while capacity.active:
        await asyncio.sleep(0.01)

    blocker = Event()
    monkeypatch.setattr(
        analysis_module, "UNIFIED_ANALYSIS_OPERATION_TIMEOUT_SECONDS", 2.0
    )
    task = asyncio.create_task(
        execute_behavioral_analysis(lambda: blocker.wait(1), capacity)  # type: ignore[arg-type]
    )
    while capacity.active == 0:
        await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert capacity.active == 1
    blocker.set()
    while capacity.active:
        await asyncio.sleep(0)


@pytest.mark.security
def test_analysis_has_no_io_execution_ml_or_vulnerability_mapping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = BehavioralAnalysisService(loaded_store())

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("external or dynamic operation is forbidden")

    monkeypatch.setattr(Path, "write_text", forbidden)
    monkeypatch.setattr(socket, "connect", forbidden)
    monkeypatch.setattr("builtins.eval", forbidden)
    monkeypatch.setattr("builtins.exec", forbidden)
    result = analyze((process_event(1),), service=service)
    assert result.ml_inference_performed is False
    assert result.vulnerability_mapping_performed is False
    assert "CVE-" not in result.model_dump_json()


@pytest.mark.integration
def test_declared_and_synthetic_analysis_apis_return_same_contract(
    client: TestClient,
) -> None:
    event = process_event(1)
    declared = client.post(
        "/api/v1/behavior/analyze",
        json={"batch": {"events": [event.model_dump(mode="json")]}},
    )
    assert declared.status_code == 200
    synthetic = client.post(
        "/api/v1/behavior/scenarios/analyze",
        json={
            "scenario": {
                "scenario_id": "api-demo",
                "scenario_kind": "normal_process_lifecycle",
                "seed": 5,
                "platform": "linux",
                "start_time": NOW.isoformat(),
                "event_count": 2,
            }
        },
    )
    assert synthetic.status_code == 200
    assert set(declared.json()) == set(synthetic.json())
    assert declared.json()["source"] == "declared_batch"
    assert synthetic.json()["source"] == "synthetic_scenario"


@pytest.mark.contract
def test_analysis_schema_and_openapi_methods(client: TestClient) -> None:
    descriptor = client.get("/api/v1/behavior/analysis/schema")
    assert descriptor.status_code == 200
    assert descriptor.json()["maximum_declared_events"] == 256
    assert descriptor.json()["maximum_synthetic_events"] == 100
    paths = client.get("/openapi.json").json()["paths"]
    assert set(paths["/api/v1/behavior/analyze"]) == {"post"}
    assert set(paths["/api/v1/behavior/scenarios/analyze"]) == {"post"}
    assert set(paths["/api/v1/behavior/analysis/schema"]) == {"get"}


@pytest.mark.security
def test_analysis_api_rejects_unknown_options_malformed_and_oversized_input(
    client: TestClient,
) -> None:
    event = process_event(1)
    body = {"batch": {"events": [event.model_dump(mode="json")]}}
    assert (
        client.post(
            "/api/v1/behavior/analyze",
            json=body | {"findings": []},
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/behavior/analyze",
            json=body | {"options": {"rule_ids": ["BR-PROC-999"]}},
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/behavior/analyze",
            content=b"{}",
            headers={"Content-Length": "600000", "Content-Type": "application/json"},
        ).status_code
        == 413
    )
    assert (
        client.post(
            "/api/v1/behavior/scenarios/analyze",
            content=b"{}",
            headers={"Content-Length": "70000", "Content-Type": "application/json"},
        ).status_code
        == 413
    )


@pytest.mark.integration
def test_analysis_api_sanitizes_capacity_limit_and_unexpected_failures(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    event = process_event(1)
    body = {"batch": {"events": [event.model_dump(mode="json")]}}

    async def limited(*args: object, **kwargs: object) -> None:
        raise BehavioralAnalysisLimitError("private deadline detail")

    monkeypatch.setattr(
        "app.api.v1.routes.behavior_analysis.execute_behavioral_analysis", limited
    )
    response = client.post("/api/v1/behavior/analyze", json=body)
    assert (
        response.status_code == 503 and "private deadline detail" not in response.text
    )

    async def full(*args: object, **kwargs: object) -> None:
        raise BehavioralAnalysisCapacityError("private capacity detail")

    monkeypatch.setattr(
        "app.api.v1.routes.behavior_analysis.execute_behavioral_analysis", full
    )
    response = client.post("/api/v1/behavior/analyze", json=body)
    assert (
        response.status_code == 429 and "private capacity detail" not in response.text
    )

    async def broken(*args: object, **kwargs: object) -> None:
        raise RuntimeError("private internal detail")

    monkeypatch.setattr(
        "app.api.v1.routes.behavior_analysis.execute_behavioral_analysis", broken
    )
    response = client.post("/api/v1/behavior/analyze", json=body)
    assert (
        response.status_code == 500 and "private internal detail" not in response.text
    )
