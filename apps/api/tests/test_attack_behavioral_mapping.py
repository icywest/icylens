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

import app.services.attack_mapping as mapping_module
from app.attack.catalog import ATTACKCatalogStore
from app.behavior.attack_mapping_policies import BUILTIN_ATTACK_MAPPING_POLICIES
from app.behavior.attack_mapping_registry import (
    AttackMappingPolicyRegistry,
    MappingPolicyValidationError,
)
from app.schemas.attack_mapping import (
    AttackMappingPolicy,
    AttackMappingRequest,
    MappingEvidenceType,
    MappingState,
)
from app.schemas.behavior import (
    ConfigurationEvent,
    ConfigurationKind,
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
)
from app.services.attack_mapping import (
    AttackMappingCapacity,
    AttackMappingCapacityError,
    AttackMappingLimitError,
    AttackMappingService,
    evaluate_attack_mapping,
)

NOW = datetime(2026, 10, 26, 14, 0, tzinfo=timezone.utc)
PROCESS_A = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
PROCESS_B = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")


def event_id(index: int) -> UUID:
    return UUID(f"10000000-0000-4000-8000-{index:012d}")


def identity(value: UUID = PROCESS_A, pid: int = 1200) -> ProcessIdentity:
    return ProcessIdentity(process_instance_id=value, pid=pid, started_at=NOW)


def common(
    index: int,
    seconds: int = 0,
    *,
    platform: EventPlatform = EventPlatform.LINUX,
    host: str = "host-a",
    synthetic: bool = False,
) -> dict[str, object]:
    timestamp = NOW + timedelta(seconds=seconds)
    source = EventSource(
        kind=(
            EventSourceKind.SYNTHETIC_GENERATOR
            if synthetic
            else EventSourceKind.DECLARED_API
        ),
        source_id="mapping-test-source",
        producer="offline fixture",
    )
    return {
        "event_id": event_id(index),
        "timestamp": timestamp,
        "host_id": host,
        "source": source,
        "platform": platform,
        "synthetic": synthetic,
        "provenance": EventProvenance(
            source_identifier=source.source_id,
            observed_at=timestamp,
            received_at=timestamp + timedelta(milliseconds=10),
            nature=EventNature.SYNTHETIC if synthetic else EventNature.DECLARED,
            missing_fields=(),
            limitations=("Offline fixture.",),
        ),
        "attributes": {},
    }


def process_event(
    index: int,
    action: ProcessAction = ProcessAction.START,
    *,
    process: ProcessIdentity | None = None,
    host: str = "host-a",
    command_line: str | None = "synthetic command context",
    synthetic: bool = False,
) -> ProcessEvent:
    return ProcessEvent(
        event_type="process",
        action=action,
        process=process or identity(),
        parent_process=None,
        executable_path="/private/tool",
        command_line=command_line,
        user_context="private-user",
        exit_code=0 if action is ProcessAction.TERMINATE else None,
        **common(index, index, host=host, synthetic=synthetic),
    )


def network_event(
    index: int,
    action: NetworkAction = NetworkAction.ATTEMPTED,
    *,
    process: ProcessIdentity | None = None,
) -> NetworkEvent:
    return NetworkEvent(
        event_type="network",
        action=action,
        local_ip="192.0.2.1",
        local_port=50000,
        remote_ip="198.51.100.1",
        remote_port=443,
        protocol=NetworkProtocol.TCP,
        process=process,
        **common(index, index),
    )


def scheduled_task(index: int = 1) -> ConfigurationEvent:
    return ConfigurationEvent(
        event_type="configuration",
        action="reported_change",
        configuration_kind=ConfigurationKind.SCHEDULED_TASK,
        target="private-task",
        previous_value=None,
        current_value="private-action",
        process=identity(),
        **common(index, index, platform=EventPlatform.WINDOWS),
    )


def file_event(index: int = 1) -> FileEvent:
    return FileEvent(
        event_type="file",
        action=FileAction.CREATE,
        file_path="/private/file",
        **common(index, index),
    )


def loaded_store() -> ATTACKCatalogStore:
    store = ATTACKCatalogStore()
    store.load()
    return store


def assess(
    events: tuple[ProcessEvent | NetworkEvent | ConfigurationEvent | FileEvent, ...],
    *,
    policy_ids: tuple[str, ...] | None = None,
    service: AttackMappingService | None = None,
):
    request = AttackMappingRequest(
        batch=EventBatch(events=events), policy_ids=policy_ids
    )
    return (service or AttackMappingService(loaded_store())).evaluate(request)


@pytest.mark.unit
def test_builtin_registry_is_sorted_versioned_and_catalog_valid() -> None:
    registry = AttackMappingPolicyRegistry()
    registry.validate_catalog(loaded_store().snapshot)
    assert [item.policy_id for item in registry.policies] == sorted(
        item.policy_id for item in registry.policies
    )
    assert {item.version for item in registry.policies} == {"1.0.0"}
    assert {item.technique_id for item in registry.policies} == {
        "T1053.005",
        "T1059",
        "T1071.001",
    }
    assert all(
        item.retired_policy == "report_never_candidate" for item in registry.policies
    )


@pytest.mark.unit
def test_registry_rejects_duplicate_and_unknown_technique() -> None:
    policy = BUILTIN_ATTACK_MAPPING_POLICIES[0]
    with pytest.raises(MappingPolicyValidationError, match="Duplicate"):
        AttackMappingPolicyRegistry((policy, policy))

    unknown = policy.model_copy(update={"technique_id": "T9999"})
    registry = AttackMappingPolicyRegistry((unknown,))
    with pytest.raises(MappingPolicyValidationError, match="unknown"):
        registry.validate_catalog(loaded_store().snapshot)


@pytest.mark.unit
def test_command_line_rule_is_insufficient_for_interpreter_mapping() -> None:
    result = assess((process_event(1),), policy_ids=("AMP-PROC-001",))
    evaluation = result.evaluations[0]
    assert evaluation.state is MappingState.INSUFFICIENT_EVIDENCE
    assert evaluation.technique is not None
    assert evaluation.technique.attack_id == "T1059"
    assert evaluation.technique.catalog_version == "19.2"
    assert evaluation.positive_evidence[0].backend_generated is True
    assert "interpreter" in " ".join(evaluation.missing_evidence).lower()
    assert result.confirmed_attack is False and result.malware_detected is False


@pytest.mark.unit
def test_tcp_443_does_not_imply_web_protocol_or_command_and_control() -> None:
    result = assess((network_event(1),), policy_ids=("AMP-NET-001",))
    evaluation = result.evaluations[0]
    assert evaluation.state is MappingState.INSUFFICIENT_EVIDENCE
    assert result.summary.candidates == 0
    assert "protocol" in " ".join(evaluation.missing_evidence).lower()
    serialized = result.model_dump_json()
    assert "does not establish HTTP, HTTPS, Command and Control" in serialized
    assert "198.51.100.1" not in serialized


@pytest.mark.unit
def test_scheduled_task_does_not_confirm_persistence() -> None:
    result = assess((scheduled_task(),), policy_ids=("AMP-CONF-001",))
    evaluation = result.evaluations[0]
    assert evaluation.state is MappingState.INSUFFICIENT_EVIDENCE
    assert set(evaluation.technique.tactic_ids) == {  # type: ignore[union-attr]
        "TA0002",
        "TA0003",
        "TA0004",
    }
    assert result.malicious_activity_confirmed is False
    assert "private-task" not in result.model_dump_json()


@pytest.mark.unit
def test_unmatched_and_absent_families_are_distinct() -> None:
    unmatched = assess(
        (process_event(1, action=ProcessAction.TERMINATE),),
        policy_ids=("AMP-PROC-001",),
    )
    assert unmatched.evaluations[0].state is MappingState.NOT_SUPPORTED

    absent = assess((file_event(),), policy_ids=("AMP-PROC-001",))
    assert absent.evaluations[0].state is MappingState.NOT_APPLICABLE


@pytest.mark.unit
def test_catalog_unavailable_is_typed_not_invented() -> None:
    store = ATTACKCatalogStore(Path("missing-catalog"))
    service = AttackMappingService(store)
    result = assess((process_event(1),), policy_ids=("AMP-PROC-001",), service=service)
    assert result.catalog_provenance is None
    assert result.evaluations[0].state is MappingState.CATALOG_UNAVAILABLE
    assert result.evaluations[0].technique is None

    registry = service.policy_registry()
    assert registry.catalog_available is False and registry.catalog_version is None


@pytest.mark.unit
@pytest.mark.parametrize(
    ("technique_id", "expected_status"),
    [("T1026", "deprecated"), ("T1002", "revoked")],
)
def test_retired_techniques_never_become_candidates(
    technique_id: str, expected_status: str
) -> None:
    base = BUILTIN_ATTACK_MAPPING_POLICIES[2]
    retired = base.model_copy(update={"technique_id": technique_id})
    service = AttackMappingService(
        loaded_store(), AttackMappingPolicyRegistry((retired,))
    )
    result = assess(
        (process_event(1),), policy_ids=(retired.policy_id,), service=service
    )
    assert result.evaluations[0].state is MappingState.RETIRED_TECHNIQUE
    assert result.evaluations[0].technique.status.value == expected_status  # type: ignore[union-attr]
    assert result.summary.candidates == 0


@pytest.mark.unit
def test_candidate_state_requires_every_minimum_requirement() -> None:
    base = BUILTIN_ATTACK_MAPPING_POLICIES[2]
    trusted_test_policy = AttackMappingPolicy(
        **(
            base.model_dump()
            | {
                "minimum_evidence": (base.minimum_evidence[0],),
                "optional_evidence": (),
                "limitations": (
                    "Test-only trusted policy exercises the all-requirements-satisfied state.",
                ),
            }
        )
    )
    service = AttackMappingService(
        loaded_store(), AttackMappingPolicyRegistry((trusted_test_policy,))
    )
    result = assess(
        (process_event(1, synthetic=True),),
        policy_ids=(trusted_test_policy.policy_id,),
        service=service,
    )
    assert result.evaluations[0].state is MappingState.CANDIDATE
    assert result.evaluations[0].positive_evidence[0].nature == (EventNature.SYNTHETIC,)
    assert "not confirmation" in result.evaluations[0].explanation.scientific_boundary


@pytest.mark.unit
def test_cross_host_process_conflict_is_contradictory_not_candidate() -> None:
    events = (
        process_event(1, host="host-a"),
        process_event(2, host="host-b"),
    )
    result = assess(events, policy_ids=("AMP-PROC-001",))
    evaluation = result.evaluations[0]
    assert evaluation.state is MappingState.NOT_SUPPORTED
    assert "PROCESS_INSTANCE_HOST_CONFLICT" in " ".join(
        evaluation.contradictory_evidence
    )


@pytest.mark.unit
def test_weak_temporal_connection_evidence_remains_weak_and_insufficient() -> None:
    events = (
        network_event(1, NetworkAction.ATTEMPTED, process=identity()),
        network_event(2, NetworkAction.ESTABLISHED, process=identity()),
    )
    result = assess(events, policy_ids=("AMP-NET-001",))
    evaluation = result.evaluations[0]
    relationship_refs = [
        item
        for item in evaluation.positive_evidence
        if item.evidence_type is MappingEvidenceType.TEMPORAL_RELATIONSHIP
    ]
    assert relationship_refs and all(
        item.strength.value == "weak" for item in relationship_refs
    )
    assert evaluation.state is MappingState.INSUFFICIENT_EVIDENCE


@pytest.mark.unit
def test_equal_timestamps_and_reordering_do_not_change_mapping_evaluations() -> None:
    first = process_event(1)
    second = process_event(2).model_copy(
        update={
            "timestamp": first.timestamp,
            "provenance": first.provenance,
        }
    )
    ordered = assess((first, second), policy_ids=("AMP-PROC-001",))
    reordered = assess((second, first), policy_ids=("AMP-PROC-001",))
    assert ordered.evaluations == reordered.evaluations
    assert ordered.summary == reordered.summary
    assert ordered.temporal_correlation_summary.equal_timestamp_groups == 1


@pytest.mark.unit
def test_request_rejects_client_evidence_unknown_duplicate_and_code() -> None:
    event = process_event(1)
    batch = {"events": [event.model_dump(mode="json")]}
    with pytest.raises(ValidationError):
        AttackMappingRequest.model_validate(
            {"batch": batch, "findings": [{"event_ids": [str(event_id(999))]}]}
        )
    with pytest.raises(ValidationError, match="duplicates"):
        AttackMappingRequest(
            batch=EventBatch(events=(event,)),
            policy_ids=("AMP-PROC-001", "AMP-PROC-001"),
        )
    with pytest.raises(ValidationError):
        AttackMappingRequest.model_validate(
            {"batch": batch, "policy_ids": ["__import__('os')"]}
        )


@pytest.mark.unit
def test_unknown_registered_policy_selection_fails_closed() -> None:
    request = AttackMappingRequest(
        batch=EventBatch(events=(process_event(1),)),
        policy_ids=("AMP-PROC-999",),
    )
    with pytest.raises(LookupError):
        AttackMappingService(loaded_store()).evaluate(request)


@pytest.mark.unit
def test_evidence_and_output_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    result = assess(
        tuple(process_event(index) for index in range(1, 20)),
        policy_ids=("AMP-PROC-001",),
    )
    assert all(
        len(reference.event_ids) <= 8
        for evaluation in result.evaluations
        for reference in evaluation.positive_evidence
    )
    monkeypatch.setattr(mapping_module, "MAX_MAPPING_OUTPUT_BYTES", 10)
    with pytest.raises(AttackMappingLimitError, match="output"):
        assess((process_event(1),), policy_ids=("AMP-PROC-001",))


@pytest.mark.unit
def test_mapping_deadline_fails_closed() -> None:
    moments = iter((0.0, 2.0))
    service = AttackMappingService(loaded_store(), clock=lambda: next(moments))
    with pytest.raises(AttackMappingLimitError, match="deadline"):
        assess((process_event(1),), policy_ids=("AMP-PROC-001",), service=service)


@pytest.mark.anyio
async def test_capacity_timeout_and_cancellation_release_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = AttackMappingRequest(batch=EventBatch(events=(process_event(1),)))
    capacity = AttackMappingCapacity(1)
    assert await capacity.try_acquire() is True
    with pytest.raises(AttackMappingCapacityError):
        await evaluate_attack_mapping(
            AttackMappingService(loaded_store()), request, capacity
        )
    await capacity.release()

    class SlowService:
        def evaluate(self, _: AttackMappingRequest) -> None:
            time.sleep(0.05)

    monkeypatch.setattr(mapping_module, "MAPPING_OPERATION_TIMEOUT_SECONDS", 0.001)
    with pytest.raises(AttackMappingLimitError, match="timed out"):
        await evaluate_attack_mapping(SlowService(), request, capacity)  # type: ignore[arg-type]
    assert capacity.active == 1
    while capacity.active:
        await asyncio.sleep(0.01)
    assert capacity.active == 0

    blocker = Event()

    class BlockingService:
        def evaluate(self, _: AttackMappingRequest) -> None:
            blocker.wait(1)

    monkeypatch.setattr(mapping_module, "MAPPING_OPERATION_TIMEOUT_SECONDS", 2.0)
    task = asyncio.create_task(
        evaluate_attack_mapping(BlockingService(), request, capacity)  # type: ignore[arg-type]
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
    assert capacity.active == 0
    await capacity.aclose()


@pytest.mark.security
def test_mapping_performs_no_io_ml_or_vulnerability_inference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = loaded_store()

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("external I/O or dynamic execution is forbidden")

    monkeypatch.setattr(Path, "write_text", forbidden)
    monkeypatch.setattr(socket, "connect", forbidden)
    monkeypatch.setattr("builtins.eval", forbidden)
    monkeypatch.setattr("builtins.exec", forbidden)
    result = assess(
        (network_event(1),),
        policy_ids=("AMP-NET-001",),
        service=AttackMappingService(store),
    )
    assert result.vulnerability_mapping_performed is False
    assert result.attribution_performed is False
    assert "CVE-" not in result.model_dump_json()


@pytest.mark.integration
def test_mapping_api_lists_policies_and_returns_conservative_assessment(
    client: TestClient,
) -> None:
    registry = client.get("/api/v1/behavior/attack/policies")
    assert registry.status_code == 200
    assert registry.json()["count"] == 3
    assert registry.json()["catalog_version"] == "19.2"
    assert registry.json()["client_definitions_accepted"] is False

    event = process_event(1)
    response = client.post(
        "/api/v1/behavior/attack/map",
        json={
            "batch": {"events": [event.model_dump(mode="json")]},
            "policy_ids": ["AMP-PROC-001"],
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["summary"]["candidates"] == 0
    assert payload["evaluations"][0]["state"] == "insufficient_evidence"
    assert payload["backend_evidence_recomputed"] is True


@pytest.mark.contract
def test_mapping_api_openapi_and_methods(client: TestClient) -> None:
    paths = client.get("/openapi.json").json()["paths"]
    assert set(paths["/api/v1/behavior/attack/map"]) == {"post"}
    assert set(paths["/api/v1/behavior/attack/policies"]) == {"get"}
    assert client.post("/api/v1/behavior/attack/policies").status_code == 405
    assert client.get("/api/v1/behavior/attack/map").status_code == 405


@pytest.mark.security
def test_mapping_api_rejects_client_findings_unknown_policy_and_oversize(
    client: TestClient,
) -> None:
    event = process_event(1)
    body = {"batch": {"events": [event.model_dump(mode="json")]}}
    assert (
        client.post(
            "/api/v1/behavior/attack/map", json=body | {"findings": []}
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/behavior/attack/map",
            json=body | {"policy_ids": ["AMP-PROC-999"]},
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/behavior/attack/map",
            content=b"{}",
            headers={"Content-Length": "600000", "Content-Type": "application/json"},
        ).status_code
        == 413
    )


@pytest.mark.integration
def test_mapping_api_sanitizes_capacity_limit_and_unexpected_failures(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    event = process_event(1)
    body = {"batch": {"events": [event.model_dump(mode="json")]}}

    async def limited(*args: object, **kwargs: object) -> None:
        raise AttackMappingLimitError("private timeout detail")

    monkeypatch.setattr(
        "app.api.v1.routes.behavior_attack.evaluate_attack_mapping", limited
    )
    response = client.post("/api/v1/behavior/attack/map", json=body)
    assert response.status_code == 503 and "private timeout detail" not in response.text

    async def full(*args: object, **kwargs: object) -> None:
        raise AttackMappingCapacityError("private capacity detail")

    monkeypatch.setattr(
        "app.api.v1.routes.behavior_attack.evaluate_attack_mapping", full
    )
    response = client.post("/api/v1/behavior/attack/map", json=body)
    assert (
        response.status_code == 429 and "private capacity detail" not in response.text
    )

    async def broken(*args: object, **kwargs: object) -> None:
        raise RuntimeError("private internal detail")

    monkeypatch.setattr(
        "app.api.v1.routes.behavior_attack.evaluate_attack_mapping", broken
    )
    response = client.post("/api/v1/behavior/attack/map", json=body)
    assert (
        response.status_code == 500 and "private internal detail" not in response.text
    )
