from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from socket import socket
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

import app.behavior.correlation as correlation_module
from app.behavior.correlation import (
    TemporalCorrelationEngine,
    TemporalCorrelationLimitError,
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
from app.schemas.behavior_correlation import (
    CorrelationPolicy,
    RelationshipConfidence,
    RelationshipState,
    RelationshipType,
    TemporalCorrelationRequest,
)

NOW = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)
PROCESS_A = UUID("11111111-1111-4111-8111-111111111111")
PROCESS_B = UUID("22222222-2222-4222-8222-222222222222")
PARENT = UUID("33333333-3333-4333-8333-333333333333")


def event_id(index: int) -> UUID:
    return UUID(f"00000000-0000-4000-8000-{index:012d}")


def identity(
    value: UUID = PROCESS_A, *, pid: int = 1234, started_at: datetime = NOW
) -> ProcessIdentity:
    return ProcessIdentity(process_instance_id=value, pid=pid, started_at=started_at)


def common(
    index: int,
    timestamp: datetime,
    *,
    host: str = "host-a",
    observed_gap: int = 0,
    received_gap: int = 0,
) -> dict[str, object]:
    observed = timestamp + timedelta(seconds=observed_gap)
    source = EventSource(
        kind=EventSourceKind.DECLARED_API,
        source_id="correlation-test-source",
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
            observed_at=observed,
            received_at=observed + timedelta(seconds=received_gap),
            nature=EventNature.DECLARED,
            missing_fields=(),
            limitations=("Offline fixture.",),
        ),
        "attributes": {},
    }


def process_event(
    index: int,
    action: ProcessAction,
    seconds: int,
    *,
    process: ProcessIdentity | None = None,
    parent: ProcessIdentity | None = None,
    host: str = "host-a",
) -> ProcessEvent:
    return ProcessEvent(
        event_type="process",
        action=action,
        process=process or identity(),
        parent_process=parent,
        executable_path="/private/example",
        command_line="/private/example --secret",
        user_context="private-user",
        exit_code=0 if action is ProcessAction.TERMINATE else None,
        **common(index, NOW + timedelta(seconds=seconds), host=host),
    )


def file_event(
    index: int,
    action: FileAction,
    seconds: int,
    *,
    path: str = "/private/a.txt",
    destination: str | None = None,
    process: ProcessIdentity | None = None,
    host: str = "host-a",
) -> FileEvent:
    return FileEvent(
        event_type="file",
        action=action,
        file_path=path,
        destination_path=destination,
        process=process,
        **common(index, NOW + timedelta(seconds=seconds), host=host),
    )


def network_event(
    index: int,
    action: NetworkAction,
    seconds: int,
    *,
    process: ProcessIdentity | None = None,
    host: str = "host-a",
) -> NetworkEvent:
    return NetworkEvent(
        event_type="network",
        action=action,
        local_ip="192.0.2.10",
        local_port=49152,
        remote_ip="198.51.100.20",
        remote_port=443,
        protocol=NetworkProtocol.TCP,
        process=process,
        **common(index, NOW + timedelta(seconds=seconds), host=host),
    )


def correlate(
    *events: ProcessEvent | FileEvent | NetworkEvent | ConfigurationEvent,
    policy: CorrelationPolicy | None = None,
    engine: TemporalCorrelationEngine | None = None,
):
    request = TemporalCorrelationRequest(
        batch=EventBatch(events=events), policy=policy or CorrelationPolicy()
    )
    return (engine or TemporalCorrelationEngine()).correlate(request)


def relation_types(result: object) -> set[RelationshipType]:
    return {item.relationship_type for item in result.relationships}  # type: ignore[attr-defined]


@pytest.mark.unit
def test_process_lifecycle_builds_deterministic_noncausal_evidence() -> None:
    start = process_event(1, ProcessAction.START, 0)
    end = process_event(2, ProcessAction.TERMINATE, 10)
    first = correlate(start, end)
    second = correlate(start, end)
    assert first == second
    assert RelationshipType.PRECEDES in relation_types(first)
    assert RelationshipType.SAME_PROCESS_INSTANCE in relation_types(first)
    assert all(not edge.causal for edge in first.relationships)
    assert first.sequences[0].event_ids == (start.event_id, end.event_id)
    assert first.processing_time_policy == "latest_received_at"
    assert first.generated_at == end.provenance.received_at


@pytest.mark.unit
def test_reordered_input_preserves_canonical_graph_semantics() -> None:
    events = (
        process_event(1, ProcessAction.START, 0),
        file_event(2, FileAction.CREATE, 2, process=identity()),
        process_event(3, ProcessAction.TERMINATE, 4),
    )
    ordered = correlate(*events)
    reversed_result = correlate(*reversed(events))
    assert ordered.nodes == reversed_result.nodes
    assert ordered.relationships == reversed_result.relationships
    assert ordered.sequences == reversed_result.sequences
    assert reversed_result.summary.input_was_out_of_order is True
    assert "INPUT_ORDER_NOT_TEMPORAL_ORDER" in {
        issue.code for issue in reversed_result.issues
    }


@pytest.mark.unit
def test_equal_timestamps_are_indeterminate_and_uuid_is_presentation_only() -> None:
    first = file_event(2, FileAction.CREATE, 0, path="/same")
    second = file_event(1, FileAction.MODIFY, 0, path="/same")
    result = correlate(first, second)
    assert [node.event_id for node in result.nodes] == [second.event_id, first.event_id]
    assert "EQUAL_EVENT_TIMES" in {issue.code for issue in result.issues}
    assert not any(
        edge.relationship_type is RelationshipType.PRECEDES
        for edge in result.relationships
    )


@pytest.mark.unit
def test_timezone_offsets_normalize_to_utc() -> None:
    offset = timezone(timedelta(hours=-6))
    timestamp = datetime(2026, 10, 26, 6, 0, tzinfo=offset)
    event = FileEvent(
        event_type="file",
        action=FileAction.CREATE,
        file_path="/offset",
        **common(1, timestamp),
    )
    result = correlate(event)
    assert result.nodes[0].event_time == NOW
    assert result.nodes[0].event_time.utcoffset() == timedelta(0)


@pytest.mark.unit
def test_future_skew_and_processing_contradictions_remain_explicit() -> None:
    event = FileEvent(
        event_type="file",
        action=FileAction.CREATE,
        file_path="/gap",
        **common(1, NOW + timedelta(hours=1), observed_gap=120, received_gap=120),
    )
    result = correlate(
        event,
        policy=CorrelationPolicy(
            processing_time=NOW,
            future_tolerance_seconds=10,
            clock_skew_seconds=30,
        ),
    )
    assert {
        "EVENT_TIME_IN_FUTURE",
        "EVENT_OBSERVATION_GAP",
        "OBSERVATION_RECEIPT_GAP",
        "PROCESSING_TIME_CONTRADICTION",
    } <= {issue.code for issue in result.issues}


@pytest.mark.unit
def test_duplicate_identity_is_deduplicated_and_conflict_reported() -> None:
    first = file_event(1, FileAction.CREATE, 0)
    duplicate = first.model_copy(update={"file_path": "/private/other.txt"})
    result = correlate(first, duplicate)
    assert len(result.nodes) == 1
    assert result.summary.submitted_event_count == 2
    issue = next(item for item in result.issues if item.code == "DUPLICATE_EVENT_ID")
    assert issue.severity.value == "error"


@pytest.mark.unit
def test_pid_reuse_does_not_create_process_identity() -> None:
    first = process_event(
        1, ProcessAction.START, 0, process=identity(PROCESS_A, pid=77)
    )
    second = process_event(
        2, ProcessAction.START, 1, process=identity(PROCESS_B, pid=77)
    )
    result = correlate(first, second)
    assert "PID_REUSE_NOT_IDENTITY" in {issue.code for issue in result.issues}
    assert not any(
        edge.relationship_type is RelationshipType.SAME_PROCESS_INSTANCE
        for edge in result.relationships
    )


@pytest.mark.unit
def test_process_identity_never_crosses_hosts() -> None:
    first = process_event(1, ProcessAction.START, 0)
    second = process_event(2, ProcessAction.TERMINATE, 1, host="host-b")
    result = correlate(first, second)
    assert "PROCESS_INSTANCE_HOST_CONFLICT" in {issue.code for issue in result.issues}
    assert not any(
        edge.relationship_type is RelationshipType.SAME_PROCESS_INSTANCE
        for edge in result.relationships
    )


@pytest.mark.unit
def test_explicit_parent_relationship_requires_present_same_host_start() -> None:
    parent_process = identity(PARENT, pid=10, started_at=NOW)
    child_process = identity(PROCESS_A, pid=11, started_at=NOW + timedelta(seconds=1))
    parent = process_event(1, ProcessAction.START, 0, process=parent_process)
    child = process_event(
        2, ProcessAction.START, 2, process=child_process, parent=parent_process
    )
    result = correlate(parent, child)
    relation = next(
        edge
        for edge in result.relationships
        if edge.relationship_type is RelationshipType.PARENT_PROCESS
    )
    assert relation.source_event_id == parent.event_id
    assert relation.confidence is RelationshipConfidence.STRONG

    absent = correlate(child)
    assert "PARENT_EVENT_IDENTITY_INSUFFICIENT" in {
        issue.code for issue in absent.issues
    }
    wrong_host = correlate(parent.model_copy(update={"host_id": "host-b"}), child)
    assert "PARENT_HOST_CONFLICT" in {issue.code for issue in wrong_host.issues}


@pytest.mark.unit
def test_process_lifecycle_contradictions_are_reported() -> None:
    termination = process_event(1, ProcessAction.TERMINATE, 2)
    later_start = process_event(2, ProcessAction.START, 3)
    result = correlate(termination, later_start)
    assert "PROCESS_LIFECYCLE_CONTRADICTION" in {issue.code for issue in result.issues}
    lone = correlate(termination)
    assert "PROCESS_START_NOT_PRESENT" in {issue.code for issue in lone.issues}


@pytest.mark.unit
def test_file_chain_is_weak_declared_identity_and_redacts_paths() -> None:
    events = (
        file_event(1, FileAction.CREATE, 0),
        file_event(2, FileAction.MODIFY, 1),
        file_event(
            3,
            FileAction.RENAME,
            2,
            destination="/private/b.txt",
        ),
        file_event(4, FileAction.DELETE, 3, path="/private/b.txt"),
    )
    result = correlate(*events)
    edges = [
        edge
        for edge in result.relationships
        if edge.relationship_type is RelationshipType.SAME_DECLARED_FILE
    ]
    assert edges and all(
        edge.confidence is RelationshipConfidence.WEAK for edge in edges
    )
    assert all(edge.state is RelationshipState.PLAUSIBLE_UNVERIFIED for edge in edges)
    serialized = result.model_dump_json()
    assert "/private/" not in serialized and "--secret" not in serialized
    assert any(
        "persistent physical-file identity" in item for item in edges[0].limitations
    )


@pytest.mark.unit
def test_same_path_on_different_hosts_is_not_file_identity() -> None:
    result = correlate(
        file_event(1, FileAction.CREATE, 0),
        file_event(2, FileAction.MODIFY, 1, host="host-b"),
    )
    assert not any(
        edge.relationship_type is RelationshipType.SAME_DECLARED_FILE
        for edge in result.relationships
    )


@pytest.mark.unit
def test_network_tuple_requires_process_and_remains_weak() -> None:
    attributed = (
        network_event(1, NetworkAction.ATTEMPTED, 0, process=identity()),
        network_event(2, NetworkAction.ESTABLISHED, 1, process=identity()),
        network_event(3, NetworkAction.CLOSED, 2, process=identity()),
    )
    result = correlate(*attributed)
    edges = [
        edge
        for edge in result.relationships
        if edge.relationship_type is RelationshipType.SAME_DECLARED_CONNECTION
    ]
    assert len(edges) == 2
    assert all(edge.confidence is RelationshipConfidence.WEAK for edge in edges)
    assert "198.51.100.20" not in result.model_dump_json()

    unresolved = correlate(network_event(4, NetworkAction.ATTEMPTED, 0))
    assert "CONNECTION_IDENTITY_INSUFFICIENT" in {
        issue.code for issue in unresolved.issues
    }


@pytest.mark.unit
def test_reused_network_tuple_outside_window_is_not_merged() -> None:
    result = correlate(
        network_event(1, NetworkAction.ATTEMPTED, 0, process=identity()),
        network_event(2, NetworkAction.ESTABLISHED, 20, process=identity()),
        policy=CorrelationPolicy(time_window_seconds=5),
    )
    assert "CONNECTION_EVENTS_OUTSIDE_WINDOW" in {issue.code for issue in result.issues}
    assert not any(
        edge.relationship_type is RelationshipType.SAME_DECLARED_CONNECTION
        for edge in result.relationships
    )

    distinct_processes = correlate(
        network_event(3, NetworkAction.ATTEMPTED, 0, process=identity(PROCESS_A)),
        network_event(4, NetworkAction.ESTABLISHED, 1, process=identity(PROCESS_B)),
    )
    assert not any(
        edge.relationship_type is RelationshipType.SAME_DECLARED_CONNECTION
        for edge in distinct_processes.relationships
    )


@pytest.mark.unit
def test_configuration_is_context_only_and_links_by_explicit_process() -> None:
    start = process_event(1, ProcessAction.START, 0)
    configuration = ConfigurationEvent(
        event_type="configuration",
        action="reported_change",
        configuration_kind=ConfigurationKind.STARTUP,
        target="private-startup-target",
        previous_value=None,
        current_value="private-value",
        process=identity(),
        **common(2, NOW + timedelta(seconds=1)),
    )
    result = correlate(start, configuration)
    assert RelationshipType.SAME_PROCESS_INSTANCE in relation_types(result)
    assert (
        result.persisted is False and result.malware_classification_performed is False
    )
    assert "private-startup-target" not in result.model_dump_json()


@pytest.mark.unit
def test_far_events_do_not_form_identity_sequence() -> None:
    result = correlate(
        process_event(1, ProcessAction.START, 0),
        process_event(2, ProcessAction.TERMINATE, 100),
        policy=CorrelationPolicy(time_window_seconds=10),
    )
    assert "PROCESS_EVENTS_OUTSIDE_WINDOW" in {issue.code for issue in result.issues}
    assert not any(
        sequence.relationship_type is RelationshipType.SAME_PROCESS_INSTANCE
        for sequence in result.sequences
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    "policy",
    [
        {"time_window_seconds": 0},
        {"time_window_seconds": 86_401},
        {"clock_skew_seconds": -1},
        {"future_tolerance_seconds": 86_401},
        {"processing_time": datetime(2026, 1, 1)},
    ],
)
def test_policy_rejects_unbounded_or_naive_values(policy: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        CorrelationPolicy.model_validate(policy)


@pytest.mark.unit
def test_relationship_and_sequence_ids_are_stable() -> None:
    events = (
        file_event(1, FileAction.CREATE, 0),
        file_event(2, FileAction.MODIFY, 1),
    )
    first = correlate(*events)
    second = correlate(*reversed(events))
    assert [edge.relationship_id for edge in first.relationships] == [
        edge.relationship_id for edge in second.relationships
    ]
    assert [sequence.sequence_id for sequence in first.sequences] == [
        sequence.sequence_id for sequence in second.sequences
    ]


@pytest.mark.unit
def test_graph_has_only_submitted_nodes_and_acyclic_precedence() -> None:
    events = tuple(
        file_event(index, FileAction.CREATE, index, path=f"/p/{index}")
        for index in range(1, 8)
    )
    result = correlate(*events)
    submitted_ids = {event.event_id for event in events}
    assert {node.event_id for node in result.nodes} == submitted_ids
    precedence = [
        edge
        for edge in result.relationships
        if edge.relationship_type is RelationshipType.PRECEDES
    ]
    node_order = {node.event_id: node.canonical_order for node in result.nodes}
    assert all(
        node_order[edge.source_event_id] < node_order[edge.target_event_id]
        for edge in precedence
    )


@pytest.mark.unit
def test_edge_limit_deadline_and_output_limit_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = tuple(
        file_event(index, FileAction.MODIFY, index, path="/same")
        for index in range(1, 6)
    )
    monkeypatch.setattr(correlation_module, "MAX_CORRELATION_EDGES", 1)
    limited = correlate(*events)
    assert limited.summary.relationships_truncated is True
    assert "RELATIONSHIP_LIMIT_REACHED" in {issue.code for issue in limited.issues}

    monkeypatch.setattr(correlation_module, "MAX_TEMPORAL_SEQUENCES", 1)
    sequence_limited = correlate(
        file_event(10, FileAction.CREATE, 0, path="/group-a"),
        file_event(11, FileAction.MODIFY, 1, path="/group-a"),
        file_event(12, FileAction.CREATE, 2, path="/group-b"),
        file_event(13, FileAction.MODIFY, 3, path="/group-b"),
    )
    assert sequence_limited.summary.sequences_truncated is True
    assert "SEQUENCE_LIMIT_REACHED" in {issue.code for issue in sequence_limited.issues}

    moments = iter((0.0, 2.0))
    with pytest.raises(TemporalCorrelationLimitError, match="deadline"):
        correlate(
            events[0], engine=TemporalCorrelationEngine(clock=lambda: next(moments))
        )

    monkeypatch.setattr(correlation_module, "MAX_CORRELATION_OUTPUT_BYTES", 10)
    with pytest.raises(TemporalCorrelationLimitError, match="output"):
        correlate(events[0])


@pytest.mark.security
def test_engine_performs_no_io_dynamic_execution_or_attack_mapping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("external or dynamic execution is forbidden")

    monkeypatch.setattr(Path, "write_text", forbidden)
    monkeypatch.setattr(socket, "connect", forbidden)
    monkeypatch.setattr("builtins.eval", forbidden)
    monkeypatch.setattr("builtins.exec", forbidden)
    result = correlate(process_event(1, ProcessAction.START, 0))
    assert result.attack_mapping_performed is False
    assert result.causal_inference_performed is False


@pytest.mark.integration
def test_temporal_api_correlates_and_exposes_schema(client: TestClient) -> None:
    start = process_event(1, ProcessAction.START, 0)
    end = process_event(2, ProcessAction.TERMINATE, 1)
    response = client.post(
        "/api/v1/behavior/sequences/correlate",
        json={
            "batch": {
                "events": [
                    start.model_dump(mode="json"),
                    end.model_dump(mode="json"),
                ]
            }
        },
    )
    assert response.status_code == 200
    assert response.json()["summary"]["unique_event_count"] == 2
    assert response.json()["causal_inference_performed"] is False

    descriptor = client.get("/api/v1/behavior/sequences/schema")
    assert descriptor.status_code == 200
    assert "same_process_instance" in descriptor.json()["relationship_types"]
    assert descriptor.json()["persistence"] is False


@pytest.mark.contract
def test_temporal_api_is_in_openapi_and_schema_is_read_only(client: TestClient) -> None:
    paths = client.get("/openapi.json").json()["paths"]
    assert "/api/v1/behavior/sequences/correlate" in paths
    assert set(paths["/api/v1/behavior/sequences/correlate"]) == {"post"}
    assert set(paths["/api/v1/behavior/sequences/schema"]) == {"get"}
    assert client.post("/api/v1/behavior/sequences/schema").status_code == 405


@pytest.mark.security
def test_temporal_api_rejects_extra_malformed_and_oversized_input(
    client: TestClient,
) -> None:
    event = file_event(1, FileAction.CREATE, 0)
    body = {"batch": {"events": [event.model_dump(mode="json")]}}
    assert (
        client.post(
            "/api/v1/behavior/sequences/correlate", json=body | {"expression": "eval"}
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/behavior/sequences/correlate",
            json=body | {"policy": {"time_window_seconds": 0}},
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/behavior/sequences/correlate",
            content=b"{}",
            headers={"Content-Length": "600000", "Content-Type": "application/json"},
        ).status_code
        == 413
    )


@pytest.mark.integration
def test_temporal_api_sanitizes_limit_and_unexpected_failures(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    event = file_event(1, FileAction.CREATE, 0)
    body = {"batch": {"events": [event.model_dump(mode="json")]}}

    def limited(*args: object, **kwargs: object) -> None:
        raise TemporalCorrelationLimitError("private limit detail")

    monkeypatch.setattr(
        "app.api.v1.routes.behavior_sequences.engine.correlate", limited
    )
    response = client.post("/api/v1/behavior/sequences/correlate", json=body)
    assert response.status_code == 503 and "private limit detail" not in response.text

    def broken(*args: object, **kwargs: object) -> None:
        raise RuntimeError("private internal detail")

    monkeypatch.setattr("app.api.v1.routes.behavior_sequences.engine.correlate", broken)
    response = client.post("/api/v1/behavior/sequences/correlate", json=body)
    assert (
        response.status_code == 500 and "private internal detail" not in response.text
    )
