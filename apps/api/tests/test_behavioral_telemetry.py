from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from socket import socket
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.behavior.generator import generate_scenario
from app.behavior.validation import validate_event_batch
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
    FileHashes,
    NetworkAction,
    NetworkEvent,
    NetworkProtocol,
    ProcessAction,
    ProcessEvent,
    ProcessIdentity,
    SyntheticScenarioKind,
    SyntheticScenarioRequest,
)

BASE_TIME = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)


def source() -> EventSource:
    return EventSource(
        kind=EventSourceKind.DECLARED_API,
        source_id="offline-test-source",
        producer="synthetic fixture",
    )


def provenance(
    timestamp: datetime = BASE_TIME, *, synthetic: bool = False
) -> EventProvenance:
    return EventProvenance(
        source_identifier=source().source_id,
        observed_at=timestamp,
        received_at=timestamp + timedelta(milliseconds=10),
        nature=EventNature.SYNTHETIC if synthetic else EventNature.DECLARED,
        missing_fields=(),
        limitations=("Synthetic fixture; no host observation.",),
    )


def process_identity(
    *, identity: UUID | None = None, pid: int = 1234, started_at: datetime = BASE_TIME
) -> ProcessIdentity:
    return ProcessIdentity(
        process_instance_id=identity or UUID("11111111-1111-4111-8111-111111111111"),
        pid=pid,
        started_at=started_at,
    )


def common(
    timestamp: datetime = BASE_TIME,
    *,
    event_id: UUID | None = None,
    host_id: str = "host-a",
) -> dict[str, object]:
    return {
        "event_id": event_id or uuid4(),
        "timestamp": timestamp,
        "host_id": host_id,
        "source": source(),
        "platform": EventPlatform.LINUX,
        "synthetic": False,
        "provenance": provenance(timestamp),
        "attributes": {"fixture": True},
    }


def process_event(
    action: ProcessAction,
    timestamp: datetime = BASE_TIME,
    *,
    identity: ProcessIdentity | None = None,
    event_id: UUID | None = None,
    host_id: str = "host-a",
) -> ProcessEvent:
    return ProcessEvent(
        event_type="process",
        action=action,
        process=identity or process_identity(),
        parent_process=None,
        executable_path="/opt/synthetic/benign-app",
        command_line="/opt/synthetic/benign-app --test",
        user_context="fixture-user",
        exit_code=0 if action is ProcessAction.TERMINATE else None,
        **common(timestamp, event_id=event_id, host_id=host_id),
    )


def scenario_request(
    kind: SyntheticScenarioKind,
    *,
    seed: int = 7,
    count: int = 2,
    platform: EventPlatform = EventPlatform.LINUX,
) -> SyntheticScenarioRequest:
    return SyntheticScenarioRequest(
        scenario_id="educational-scenario",
        scenario_kind=kind,
        seed=seed,
        platform=platform,
        start_time=BASE_TIME,
        event_count=count,
    )


@pytest.mark.unit
def test_process_lifecycle_contract_and_validation() -> None:
    start = process_event(ProcessAction.START)
    end = process_event(ProcessAction.TERMINATE, BASE_TIME + timedelta(seconds=1))
    result = validate_event_batch(EventBatch(events=(start, end)))
    assert result.valid is True
    assert result.issues == ()
    assert start.process.process_instance_id == end.process.process_instance_id


@pytest.mark.unit
def test_file_contract_supports_create_modify_delete_and_rename() -> None:
    events = (
        FileEvent(
            event_type="file",
            action=FileAction.CREATE,
            file_path="/tmp/synthetic-a.txt",
            hashes=FileHashes(sha256="a" * 64, sha1=None),
            process=process_identity(),
            **common(),
        ),
        FileEvent(
            event_type="file",
            action=FileAction.MODIFY,
            file_path="/tmp/synthetic-a.txt",
            process=process_identity(),
            **common(BASE_TIME + timedelta(seconds=1)),
        ),
        FileEvent(
            event_type="file",
            action=FileAction.RENAME,
            file_path="/tmp/synthetic-a.txt",
            destination_path="/tmp/synthetic-b.txt",
            **common(BASE_TIME + timedelta(seconds=2)),
        ),
        FileEvent(
            event_type="file",
            action=FileAction.DELETE,
            file_path="/tmp/synthetic-b.txt",
            **common(BASE_TIME + timedelta(seconds=3)),
        ),
    )
    result = validate_event_batch(EventBatch(events=events))
    assert result.valid is True
    assert not result.issues


@pytest.mark.unit
@pytest.mark.parametrize(
    ("local_ip", "remote_ip"),
    [("192.0.2.1", "198.51.100.1"), ("2001:db8::1", "2001:db8::2")],
)
def test_network_contract_validates_ipv4_and_ipv6(
    local_ip: str, remote_ip: str
) -> None:
    event = NetworkEvent(
        event_type="network",
        action=NetworkAction.ATTEMPTED,
        local_ip=local_ip,
        local_port=0,
        remote_ip=remote_ip,
        remote_port=443,
        protocol=NetworkProtocol.TCP,
        process=None,
        **common(),
    )
    assert str(event.local_ip) == local_ip
    assert event.model_dump(mode="json")["remote_ip"] == remote_ip


@pytest.mark.unit
@pytest.mark.parametrize("kind", list(ConfigurationKind))
def test_configuration_contract_is_descriptive(kind: ConfigurationKind) -> None:
    event = ConfigurationEvent(
        event_type="configuration",
        action="reported_change",
        configuration_kind=kind,
        target="synthetic-target",
        previous_value=None,
        current_value="declared-value",
        process=None,
        **common(),
    )
    assert validate_event_batch(EventBatch(events=(event,))).valid is True


@pytest.mark.unit
def test_missing_optional_fields_remain_explicit() -> None:
    event = FileEvent(
        event_type="file",
        action=FileAction.CREATE,
        file_path="/tmp/synthetic.txt",
        hashes=None,
        process=None,
        **common(),
    )
    assert event.hashes is None and event.process is None


@pytest.mark.unit
@pytest.mark.parametrize(
    "mutation",
    [
        {"timestamp": datetime(2026, 1, 1)},
        {"synthetic": True},
        {"host_id": ""},
        {"schema_version": "2.0.0"},
        {"source": EventSource(kind=EventSourceKind.DECLARED_API, source_id="other")},
    ],
)
def test_common_event_contract_rejects_inconsistent_data(
    mutation: dict[str, object],
) -> None:
    values = common()
    values.update(mutation)
    with pytest.raises(ValidationError):
        FileEvent(
            event_type="file",
            action=FileAction.CREATE,
            file_path="/tmp/synthetic.txt",
            **values,
        )


@pytest.mark.unit
def test_family_specific_contradictions_are_rejected() -> None:
    with pytest.raises(ValidationError):
        process_event(ProcessAction.START).model_copy(update={"exit_code": 1})
        ProcessEvent.model_validate(
            process_event(ProcessAction.START).model_dump() | {"exit_code": 1}
        )
    with pytest.raises(ValidationError):
        FileEvent(
            event_type="file",
            action=FileAction.RENAME,
            file_path="a",
            destination_path=None,
            **common(),
        )
    with pytest.raises(ValidationError):
        ConfigurationEvent(
            event_type="configuration",
            action="reported_change",
            configuration_kind=ConfigurationKind.SERVICE,
            target="service",
            previous_value=None,
            current_value=None,
            **common(),
        )
    with pytest.raises(ValidationError):
        FileHashes(sha256=None, sha1=None)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("field", "value"),
    [("local_ip", "999.1.1.1"), ("local_port", -1), ("remote_port", 65536)],
)
def test_network_rejects_invalid_addresses_and_ports(field: str, value: object) -> None:
    values: dict[str, object] = {
        "event_type": "network",
        "action": NetworkAction.ATTEMPTED,
        "local_ip": "192.0.2.1",
        "local_port": 50000,
        "remote_ip": "198.51.100.1",
        "remote_port": 443,
        "protocol": NetworkProtocol.TCP,
        **common(),
    }
    values[field] = value
    with pytest.raises(ValidationError):
        NetworkEvent.model_validate(values)


@pytest.mark.unit
def test_attribute_depth_type_and_event_size_are_bounded() -> None:
    nested: object = "value"
    for _ in range(6):
        nested = {"level": nested}
    with pytest.raises(ValidationError, match="nesting"):
        FileEvent(
            event_type="file",
            action=FileAction.CREATE,
            file_path="a",
            **(common() | {"attributes": {"nested": nested}}),
        )
    with pytest.raises(ValidationError, match="unsupported"):
        FileEvent(
            event_type="file",
            action=FileAction.CREATE,
            file_path="a",
            **(common() | {"attributes": {"bad": object()}}),
        )
    with pytest.raises(ValidationError, match="serialized size"):
        FileEvent(
            event_type="file",
            action=FileAction.CREATE,
            file_path="a",
            **(common() | {"attributes": {f"k{i}": "x" * 600 for i in range(64)}}),
        )


@pytest.mark.unit
def test_batch_semantics_find_duplicates_order_and_process_conflicts() -> None:
    identity = process_identity()
    shared_id = uuid4()
    late = process_event(
        ProcessAction.TERMINATE,
        BASE_TIME + timedelta(seconds=2),
        identity=identity,
        event_id=shared_id,
        host_id="host-b",
    )
    start = process_event(ProcessAction.START, identity=identity, event_id=shared_id)
    result = validate_event_batch(EventBatch(events=(late, start)))
    codes = {issue.code for issue in result.issues}
    assert result.valid is False
    assert {
        "DUPLICATE_EVENT_ID",
        "EVENTS_OUT_OF_ORDER",
        "PROCESS_HOST_CONFLICT",
    } <= codes


@pytest.mark.unit
def test_network_state_does_not_promote_attempt_to_established() -> None:
    established = NetworkEvent(
        event_type="network",
        action=NetworkAction.ESTABLISHED,
        local_ip="192.0.2.1",
        local_port=50000,
        remote_ip="198.51.100.1",
        remote_port=443,
        protocol=NetworkProtocol.TCP,
        **common(),
    )
    result = validate_event_batch(EventBatch(events=(established,)))
    assert result.valid is False
    assert result.issues[0].code == "ESTABLISHED_WITHOUT_ATTEMPT"


@pytest.mark.unit
@pytest.mark.parametrize("kind", list(SyntheticScenarioKind))
def test_all_synthetic_scenarios_are_deterministic_and_bounded(
    kind: SyntheticScenarioKind,
) -> None:
    request = scenario_request(kind, count=2)
    first = generate_scenario(request)
    second = generate_scenario(request)
    assert first == second
    assert len(first.events) == 2
    assert first.metadata.host_id.startswith("synthetic-host-")
    assert all(event.synthetic for event in first.events)
    assert "not an endpoint observation" in first.disclaimer


@pytest.mark.unit
def test_seed_platform_and_configuration_change_output() -> None:
    first = generate_scenario(
        scenario_request(SyntheticScenarioKind.FILE_SEQUENCE, seed=1)
    )
    second = generate_scenario(
        scenario_request(SyntheticScenarioKind.FILE_SEQUENCE, seed=2)
    )
    windows = generate_scenario(
        scenario_request(
            SyntheticScenarioKind.CONFIGURATION_CHANGE,
            seed=1,
            count=1,
            platform=EventPlatform.WINDOWS,
        )
    )
    assert first != second
    assert windows.events[0].platform is EventPlatform.WINDOWS
    assert isinstance(windows.events[0], ConfigurationEvent)


@pytest.mark.unit
def test_inconsistent_scenarios_report_limits_without_attack_labels() -> None:
    expected = {
        SyntheticScenarioKind.INCOMPLETE_SEQUENCE: "PROCESS_LIFECYCLE_INCOMPLETE",
        SyntheticScenarioKind.OUT_OF_ORDER: "EVENTS_OUT_OF_ORDER",
        SyntheticScenarioKind.DUPLICATE_EVENTS: "DUPLICATE_EVENT_ID",
        SyntheticScenarioKind.INCONSISTENT_PROCESS: "INCONSISTENT_PROCESS_PARENT",
        SyntheticScenarioKind.CONTRADICTORY_DATA: "ESTABLISHED_WITHOUT_ATTEMPT",
    }
    for kind, code in expected.items():
        scenario = generate_scenario(scenario_request(kind))
        assert code in {issue.code for issue in scenario.validation.issues}
        serialized = scenario.model_dump_json().lower()
        assert "malware" not in serialized
        assert "attack technique" not in serialized


@pytest.mark.unit
def test_scenario_cardinality_seed_and_time_are_strict() -> None:
    with pytest.raises(ValidationError):
        scenario_request(SyntheticScenarioKind.NORMAL_PROCESS, count=1)
    with pytest.raises(ValidationError):
        scenario_request(SyntheticScenarioKind.DUPLICATE_EVENTS, count=1)
    with pytest.raises(ValidationError):
        scenario_request(SyntheticScenarioKind.FILE_SEQUENCE, seed=-1)
    with pytest.raises(ValidationError):
        SyntheticScenarioRequest(
            scenario_id="scenario",
            scenario_kind=SyntheticScenarioKind.CONFIGURATION_CHANGE,
            seed=1,
            platform=EventPlatform.LINUX,
            start_time=datetime(2026, 1, 1),
            event_count=1,
        )


@pytest.mark.security
def test_generator_performs_no_file_or_network_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("external I/O is forbidden")

    monkeypatch.setattr(Path, "write_text", forbidden)
    monkeypatch.setattr(socket, "connect", forbidden)
    scenario = generate_scenario(scenario_request(SyntheticScenarioKind.NORMAL_PROCESS))
    assert len(scenario.events) == 2


@pytest.mark.integration
def test_behavior_api_schema_validation_and_generation(client: TestClient) -> None:
    descriptor = client.get("/api/v1/behavior/schema")
    assert descriptor.status_code == 200
    assert descriptor.json()["attack_mapping"] is False
    assert descriptor.json()["persistence"] is False

    scenario = scenario_request(SyntheticScenarioKind.NETWORK_SEQUENCE)
    generated = client.post(
        "/api/v1/behavior/scenarios/generate",
        json=scenario.model_dump(mode="json"),
    )
    assert generated.status_code == 200
    payload = generated.json()
    assert payload["metadata"]["seed"] == 7
    assert payload["validation"]["valid"] is True

    validation = client.post(
        "/api/v1/behavior/events/validate", json={"events": payload["events"]}
    )
    assert validation.status_code == 200
    assert validation.json()["event_count"] == 2


@pytest.mark.contract
def test_behavior_openapi_has_typed_read_write_contracts(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    assert "/api/v1/behavior/events/validate" in schema["paths"]
    assert "/api/v1/behavior/scenarios/generate" in schema["paths"]
    request_schema = schema["paths"]["/api/v1/behavior/events/validate"]["post"][
        "requestBody"
    ]["content"]["application/json"]["schema"]
    assert request_schema["$ref"].endswith("/EventBatch")
    assert set(schema["paths"]["/api/v1/behavior/schema"]) == {"get"}


@pytest.mark.security
def test_behavior_api_rejects_invalid_and_oversized_requests(
    client: TestClient,
) -> None:
    assert (
        client.post("/api/v1/behavior/events/validate", content=b"{").status_code == 422
    )
    assert (
        client.post(
            "/api/v1/behavior/events/validate",
            content=b"{}",
            headers={"Content-Length": "600000", "Content-Type": "application/json"},
        ).status_code
        == 413
    )
    assert (
        client.post(
            "/api/v1/behavior/events/validate",
            content=b"{}",
            headers={"Content-Length": "invalid", "Content-Type": "application/json"},
        ).status_code
        == 400
    )
    assert client.post("/api/v1/behavior/schema").status_code == 405


@pytest.mark.unit
@pytest.mark.parametrize(
    "attributes",
    [
        {"text": "x" * 4097},
        {f"key-{index}": index for index in range(65)},
        {"": "value"},
        {"items": list(range(65))},
    ],
)
def test_additional_attribute_limits(attributes: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        FileEvent(
            event_type="file",
            action=FileAction.CREATE,
            file_path="a",
            **(common() | {"attributes": attributes}),
        )


@pytest.mark.unit
def test_provenance_and_process_timeline_constraints() -> None:
    with pytest.raises(ValidationError, match="received_at"):
        EventProvenance(
            source_identifier="source",
            observed_at=BASE_TIME,
            received_at=BASE_TIME - timedelta(seconds=1),
            nature=EventNature.DECLARED,
            missing_fields=(),
            limitations=(),
        )
    with pytest.raises(ValidationError, match="duplicates"):
        EventProvenance(
            source_identifier="source",
            observed_at=BASE_TIME,
            received_at=BASE_TIME,
            nature=EventNature.DECLARED,
            missing_fields=("user", "user"),
            limitations=(),
        )
    with pytest.raises(ValidationError, match="observed_at"):
        FileEvent(
            event_type="file",
            action=FileAction.CREATE,
            file_path="a",
            **(
                common()
                | {
                    "timestamp": BASE_TIME + timedelta(seconds=1),
                    "provenance": provenance(BASE_TIME),
                }
            ),
        )
    future = process_identity(started_at=BASE_TIME + timedelta(seconds=1))
    with pytest.raises(ValidationError, match="start time"):
        process_event(ProcessAction.START, identity=future)
    identity = process_identity()
    with pytest.raises(ValidationError, match="own parent"):
        ProcessEvent(
            event_type="process",
            action=ProcessAction.START,
            process=identity,
            parent_process=identity,
            executable_path="/synthetic",
            **common(),
        )


@pytest.mark.unit
def test_additional_batch_consistency_transitions() -> None:
    identity = process_identity()
    parent_on_other_host = process_event(
        ProcessAction.START, identity=identity, host_id="host-b"
    )
    child = ProcessEvent(
        event_type="process",
        action=ProcessAction.START,
        process=process_identity(identity=uuid4(), pid=2000),
        parent_process=identity,
        executable_path="/synthetic/child",
        **common(BASE_TIME + timedelta(seconds=1), host_id="host-a"),
    )
    repeated_start = process_event(
        ProcessAction.START,
        BASE_TIME + timedelta(seconds=2),
        identity=identity,
        host_id="host-b",
    )
    modification = FileEvent(
        event_type="file",
        action=FileAction.MODIFY,
        file_path="/not-created-in-batch",
        **common(BASE_TIME + timedelta(seconds=3)),
    )
    closed = NetworkEvent(
        event_type="network",
        action=NetworkAction.CLOSED,
        local_ip="192.0.2.1",
        local_port=50000,
        remote_ip="198.51.100.1",
        remote_port=443,
        protocol=NetworkProtocol.TCP,
        **common(BASE_TIME + timedelta(seconds=4)),
    )
    result = validate_event_batch(
        EventBatch(
            events=(parent_on_other_host, child, repeated_start, modification, closed)
        )
    )
    codes = {issue.code for issue in result.issues}
    assert {
        "PROCESS_PARENT_HOST_CONFLICT",
        "DUPLICATE_PROCESS_START",
        "FILE_MODIFY_WITHOUT_CREATE",
        "CLOSED_WITHOUT_ESTABLISHED",
    } <= codes


@pytest.mark.unit
def test_batch_serialized_size_is_reported_without_io() -> None:
    events = tuple(
        FileEvent(
            event_type="file",
            action=FileAction.CREATE,
            file_path=f"/synthetic/{index}",
            **(
                common(BASE_TIME + timedelta(seconds=index))
                | {"attributes": {f"field-{n}": "x" * 4000 for n in range(7)}}
            ),
        )
        for index in range(20)
    )
    result = validate_event_batch(EventBatch(events=events))
    assert "BATCH_SIZE_EXCEEDED" in {issue.code for issue in result.issues}


@pytest.mark.unit
def test_windows_generator_uses_descriptive_windows_paths() -> None:
    scenario = generate_scenario(
        scenario_request(
            SyntheticScenarioKind.FILE_SEQUENCE, platform=EventPlatform.WINDOWS
        )
    )
    assert isinstance(scenario.events[0], FileEvent)
    assert scenario.events[0].file_path.startswith("C:\\SyntheticLab")


@pytest.mark.integration
def test_behavior_api_sanitizes_unexpected_failures(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*args: object, **kwargs: object) -> None:
        raise RuntimeError("sensitive internal detail")

    event = FileEvent(
        event_type="file",
        action=FileAction.CREATE,
        file_path="/synthetic",
        **common(),
    )
    monkeypatch.setattr("app.api.v1.routes.behavior.validate_event_batch", fail)
    response = client.post(
        "/api/v1/behavior/events/validate",
        json=EventBatch(events=(event,)).model_dump(mode="json"),
    )
    assert response.status_code == 500
    assert "sensitive" not in response.text

    monkeypatch.setattr("app.api.v1.routes.behavior.generate_scenario", fail)
    response = client.post(
        "/api/v1/behavior/scenarios/generate",
        json=scenario_request(
            SyntheticScenarioKind.CONFIGURATION_CHANGE, count=1
        ).model_dump(mode="json"),
    )
    assert response.status_code == 500
    assert "sensitive" not in response.text
