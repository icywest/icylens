from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from socket import socket
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

import app.behavior.rule_engine as engine_module
from app.behavior.generator import generate_scenario
from app.behavior.rule_engine import BehavioralRuleEngine, RuleEvaluationLimitError
from app.behavior.rule_registry import (
    DEFAULT_RULE_REGISTRY,
    RuleRegistry,
    RuleRegistryValidationError,
    UnknownRuleError,
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
    SyntheticScenarioKind,
    SyntheticScenarioRequest,
)
from app.schemas.behavior_rules import (
    MAX_EVIDENCE_PER_FINDING,
    BehavioralRule,
    RuleEvaluationRequest,
    RuleMatchStatus,
)

NOW = datetime(2026, 10, 26, 16, 0, tzinfo=timezone.utc)


def event_source() -> EventSource:
    return EventSource(
        kind=EventSourceKind.DECLARED_API,
        source_id="controlled-rule-fixture",
        producer="offline tests",
    )


def event_provenance(timestamp: datetime = NOW) -> EventProvenance:
    return EventProvenance(
        source_identifier=event_source().source_id,
        observed_at=timestamp,
        received_at=timestamp + timedelta(milliseconds=1),
        nature=EventNature.DECLARED,
        missing_fields=(),
        limitations=("Controlled synthetic fixture.",),
    )


def identity(
    *,
    value: UUID | None = None,
    pid: int = 1200,
    started_at: datetime = NOW,
) -> ProcessIdentity:
    return ProcessIdentity(
        process_instance_id=value or UUID("11111111-1111-4111-8111-111111111111"),
        pid=pid,
        started_at=started_at,
    )


def common(
    timestamp: datetime = NOW,
    *,
    event_id: UUID | None = None,
    host_id: str = "host-a",
) -> dict[str, object]:
    return {
        "event_id": event_id or uuid4(),
        "timestamp": timestamp,
        "host_id": host_id,
        "source": event_source(),
        "platform": EventPlatform.LINUX,
        "synthetic": False,
        "provenance": event_provenance(timestamp),
        "attributes": {},
    }


def process_event(
    *,
    action: ProcessAction = ProcessAction.START,
    process: ProcessIdentity | None = None,
    parent: ProcessIdentity | None = None,
    command_line: str | None = "/opt/educational --fixture",
    timestamp: datetime = NOW,
    host_id: str = "host-a",
) -> ProcessEvent:
    return ProcessEvent(
        event_type="process",
        action=action,
        process=process or identity(),
        parent_process=parent,
        executable_path="/opt/educational",
        command_line=command_line,
        user_context=None,
        exit_code=0 if action is ProcessAction.TERMINATE else None,
        **common(timestamp, host_id=host_id),
    )


def file_event(
    action: FileAction,
    *,
    timestamp: datetime = NOW,
    process: ProcessIdentity | None = None,
    path: str = "/tmp/controlled.txt",
    destination: str | None = None,
) -> FileEvent:
    return FileEvent(
        event_type="file",
        action=action,
        file_path=path,
        destination_path=destination,
        hashes=None,
        process=process,
        **common(timestamp),
    )


def network_event(
    action: NetworkAction,
    *,
    timestamp: datetime = NOW,
    process: ProcessIdentity | None = None,
    remote_port: int = 443,
) -> NetworkEvent:
    return NetworkEvent(
        event_type="network",
        action=action,
        local_ip="192.0.2.10",
        local_port=50000,
        remote_ip="198.51.100.20",
        remote_port=remote_port,
        protocol=NetworkProtocol.TCP,
        process=process,
        **common(timestamp),
    )


def configuration_event(
    kind: ConfigurationKind,
    *,
    previous: str | None,
    current: str | None,
) -> ConfigurationEvent:
    return ConfigurationEvent(
        event_type="configuration",
        action="reported_change",
        configuration_kind=kind,
        target="controlled-target",
        previous_value=previous,
        current_value=current,
        process=None,
        **common(),
    )


def evaluate(
    events: tuple[ProcessEvent | FileEvent | NetworkEvent | ConfigurationEvent, ...],
    *rule_ids: str,
    engine: BehavioralRuleEngine | None = None,
):
    request = RuleEvaluationRequest(
        batch=EventBatch(events=events),
        rule_ids=rule_ids or None,
    )
    return (engine or BehavioralRuleEngine()).evaluate(request)


def finding(result, rule_id: str):
    return next(item for item in result.findings if item.rule_id == rule_id)


@pytest.mark.unit
def test_builtin_registry_is_unique_sorted_and_immutable() -> None:
    ids = tuple(rule.rule_id for rule in DEFAULT_RULE_REGISTRY.rules)
    assert len(ids) == 12
    assert ids == tuple(sorted(ids))
    assert len(set(ids)) == len(ids)
    with pytest.raises(ValidationError):
        DEFAULT_RULE_REGISTRY.rules[0].name = "changed"


@pytest.mark.unit
def test_registry_rejects_duplicate_and_empty_definitions() -> None:
    rule = DEFAULT_RULE_REGISTRY.rules[0]
    with pytest.raises(RuleRegistryValidationError, match="Duplicate"):
        RuleRegistry((rule, rule))
    with pytest.raises(RuleRegistryValidationError, match="empty"):
        RuleRegistry(())


@pytest.mark.unit
def test_rule_selection_is_stable_and_unknown_ids_fail() -> None:
    selected = DEFAULT_RULE_REGISTRY.select(("BR-NET-003", "BR-FILE-001"))
    assert tuple(rule.rule_id for rule in selected) == (
        "BR-FILE-001",
        "BR-NET-003",
    )
    with pytest.raises(UnknownRuleError):
        DEFAULT_RULE_REGISTRY.select(("BR-NET-999",))


@pytest.mark.unit
def test_process_rules_match_not_match_and_insufficient_evidence() -> None:
    no_parent = process_event(parent=None, command_line=None)
    result = evaluate((no_parent,), "BR-PROC-001", "BR-PROC-002", "BR-PROC-003")
    assert finding(result, "BR-PROC-001").result is RuleMatchStatus.MATCHED
    assert (
        finding(result, "BR-PROC-002").result is RuleMatchStatus.INSUFFICIENT_EVIDENCE
    )
    assert (
        finding(result, "BR-PROC-003").result is RuleMatchStatus.INSUFFICIENT_EVIDENCE
    )

    parent = identity(started_at=NOW - timedelta(minutes=1))
    contextual = process_event(parent=parent)
    result = evaluate((contextual,), "BR-PROC-001", "BR-PROC-002", "BR-PROC-003")
    assert finding(result, "BR-PROC-001").result is RuleMatchStatus.NOT_MATCHED
    assert finding(result, "BR-PROC-002").result is RuleMatchStatus.NOT_MATCHED
    assert finding(result, "BR-PROC-003").result is RuleMatchStatus.MATCHED


@pytest.mark.unit
def test_inconsistent_parent_time_and_host_match_process_rule() -> None:
    future_parent = identity(
        value=uuid4(), pid=10, started_at=NOW + timedelta(seconds=1)
    )
    child = process_event(parent=future_parent)
    assert (
        finding(evaluate((child,), "BR-PROC-002"), "BR-PROC-002").result
        is RuleMatchStatus.MATCHED
    )

    parent_record = process_event(
        process=future_parent,
        parent=None,
        host_id="host-b",
        timestamp=NOW + timedelta(seconds=1),
    )
    child = process_event(parent=future_parent, host_id="host-a")
    result = evaluate((child, parent_record), "BR-PROC-002")
    assert finding(result, "BR-PROC-002").result is RuleMatchStatus.MATCHED


@pytest.mark.unit
def test_command_line_evidence_is_bounded_and_content_is_not_returned() -> None:
    secret = "private-token-" + "x" * 500
    result = evaluate((process_event(command_line=secret),), "BR-PROC-003")
    serialized = result.model_dump_json()
    evidence = finding(result, "BR-PROC-003").evidence[0]
    assert secret not in serialized
    values = {field.field: field for field in evidence.fields}
    assert values["command_line_present"].value is True
    assert values["command_line_length"].value == len(secret)
    assert values["command_line_length"].redacted is True


@pytest.mark.unit
def test_file_rules_use_same_batch_order_and_declared_metadata() -> None:
    created = file_event(FileAction.CREATE, process=identity())
    modified = file_event(
        FileAction.MODIFY,
        timestamp=NOW + timedelta(seconds=1),
        process=identity(),
    )
    rename = file_event(
        FileAction.RENAME,
        timestamp=NOW + timedelta(seconds=2),
        destination="/tmp/renamed.txt",
        process=None,
    )
    result = evaluate(
        (created, modified, rename),
        "BR-FILE-001",
        "BR-FILE-002",
        "BR-FILE-003",
    )
    assert all(item.result is RuleMatchStatus.MATCHED for item in result.findings)
    assert finding(result, "BR-FILE-001").event_ids == (modified.event_id,)
    assert finding(result, "BR-FILE-002").event_ids == (rename.event_id,)


@pytest.mark.unit
def test_network_rules_distinguish_later_state_and_process_attribution() -> None:
    attempt = network_event(NetworkAction.ATTEMPTED, process=identity())
    established = network_event(
        NetworkAction.ESTABLISHED,
        timestamp=NOW + timedelta(seconds=1),
        process=identity(),
    )
    result = evaluate((attempt, established), "BR-NET-001", "BR-NET-002", "BR-NET-003")
    assert finding(result, "BR-NET-001").result is RuleMatchStatus.NOT_MATCHED
    assert finding(result, "BR-NET-002").result is RuleMatchStatus.NOT_MATCHED
    assert finding(result, "BR-NET-003").result is RuleMatchStatus.MATCHED

    unresolved = network_event(NetworkAction.ATTEMPTED, process=None)
    unattributed = network_event(NetworkAction.ESTABLISHED, process=None)
    assert (
        finding(evaluate((unresolved,), "BR-NET-001"), "BR-NET-001").result
        is RuleMatchStatus.MATCHED
    )
    assert (
        finding(evaluate((unattributed,), "BR-NET-002"), "BR-NET-002").result
        is RuleMatchStatus.MATCHED
    )


@pytest.mark.unit
def test_configuration_rules_report_facts_not_maliciousness() -> None:
    task = configuration_event(
        ConfigurationKind.SCHEDULED_TASK, previous=None, current="enabled"
    )
    service = configuration_event(
        ConfigurationKind.SERVICE, previous="manual", current="automatic"
    )
    result = evaluate((task, service), "BR-CONF-001", "BR-CONF-002", "BR-CONF-003")
    assert all(item.result is RuleMatchStatus.MATCHED for item in result.findings)
    assert result.malware_classification_performed is False
    assert result.attack_mapping_performed is False
    assert all(
        "malicious activity" in item.security_interpretation for item in result.findings
    )


@pytest.mark.unit
def test_rules_for_absent_families_are_not_applicable() -> None:
    result = evaluate(
        (configuration_event(ConfigurationKind.STARTUP, previous="off", current="on"),),
        "BR-PROC-001",
        "BR-FILE-001",
        "BR-NET-001",
    )
    assert result.summary.not_applicable == 3
    assert all(
        item.result is RuleMatchStatus.NOT_APPLICABLE for item in result.findings
    )


@pytest.mark.unit
def test_disabled_rule_is_not_applicable_even_when_condition_matches() -> None:
    disabled = DEFAULT_RULE_REGISTRY.rules[0].model_copy(update={"enabled": False})
    engine = BehavioralRuleEngine(RuleRegistry((disabled,)))
    event = configuration_event(ConfigurationKind.STARTUP, previous="off", current="on")
    result = evaluate((event,), disabled.rule_id, engine=engine)
    assert result.findings[0].result is RuleMatchStatus.NOT_APPLICABLE


@pytest.mark.unit
def test_duplicate_events_are_reported_and_evidence_is_deduplicated() -> None:
    event = file_event(FileAction.CREATE, process=None)
    result = evaluate((event, event), "BR-FILE-003")
    assert "DUPLICATE_EVENT_ID" in {
        issue.code for issue in result.batch_validation.issues
    }
    assert result.findings[0].event_ids == (event.event_id,)


@pytest.mark.unit
def test_evidence_is_capped_and_finding_order_is_deterministic() -> None:
    events = tuple(
        file_event(
            FileAction.CREATE,
            timestamp=NOW + timedelta(seconds=index),
            process=None,
            path=f"/tmp/{index}.txt",
        )
        for index in range(MAX_EVIDENCE_PER_FINDING + 3)
    )
    first = evaluate(events, "BR-FILE-003", "BR-FILE-001")
    second = evaluate(events, "BR-FILE-001", "BR-FILE-003")
    assert first == second
    capped = finding(first, "BR-FILE-003")
    assert len(capped.evidence) == MAX_EVIDENCE_PER_FINDING
    assert any("truncated" in limitation for limitation in capped.limitations)


@pytest.mark.unit
def test_rule_request_rejects_duplicates_and_malformed_ids() -> None:
    batch = EventBatch(events=(file_event(FileAction.CREATE),))
    with pytest.raises(ValidationError, match="duplicates"):
        RuleEvaluationRequest(batch=batch, rule_ids=("BR-FILE-001", "BR-FILE-001"))
    with pytest.raises(ValidationError):
        RuleEvaluationRequest(batch=batch, rule_ids=("__import__('os')",))


@pytest.mark.unit
def test_rule_count_deadline_and_output_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    template = DEFAULT_RULE_REGISTRY.rules[0]
    rules: list[BehavioralRule] = []
    for index in range(33):
        rules.append(
            template.model_copy(update={"rule_id": f"BR-CONF-{100 + index:03d}"})
        )
    oversized = BehavioralRuleEngine(RuleRegistry(rules))
    event = configuration_event(ConfigurationKind.STARTUP, previous="off", current="on")
    with pytest.raises(RuleEvaluationLimitError, match="Rule count"):
        evaluate((event,), engine=oversized)

    moments = iter((0.0, 2.0))
    deadline = BehavioralRuleEngine(clock=lambda: next(moments))
    with pytest.raises(RuleEvaluationLimitError, match="deadline"):
        evaluate((event,), "BR-CONF-001", engine=deadline)

    monkeypatch.setattr(engine_module, "MAX_RULE_OUTPUT_BYTES", 10)
    with pytest.raises(RuleEvaluationLimitError, match="output"):
        evaluate((event,), "BR-CONF-001")


@pytest.mark.security
def test_engine_performs_no_filesystem_network_or_dynamic_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("external or dynamic execution is forbidden")

    monkeypatch.setattr(Path, "write_text", forbidden)
    monkeypatch.setattr(socket, "connect", forbidden)
    monkeypatch.setattr("builtins.eval", forbidden)
    monkeypatch.setattr("builtins.exec", forbidden)
    result = evaluate(
        (network_event(NetworkAction.ATTEMPTED),), "BR-NET-001", "BR-NET-003"
    )
    assert result.summary.matched == 2


@pytest.mark.integration
def test_rule_api_lists_and_evaluates_typed_registry(client: TestClient) -> None:
    registry = client.get("/api/v1/behavior/rules")
    assert registry.status_code == 200
    assert registry.json()["count"] == 12
    assert registry.json()["mutable_from_http"] is False

    scenario = generate_scenario(
        SyntheticScenarioRequest(
            scenario_id="rule-api",
            scenario_kind=SyntheticScenarioKind.NETWORK_SEQUENCE,
            seed=9,
            platform=EventPlatform.LINUX,
            start_time=NOW,
            event_count=2,
        )
    )
    response = client.post(
        "/api/v1/behavior/rules/evaluate",
        json={
            "batch": {
                "events": [event.model_dump(mode="json") for event in scenario.events]
            },
            "rule_ids": ["BR-NET-001", "BR-NET-003"],
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["summary"]["evaluated_rules"] == 2
    assert payload["attack_mapping_performed"] is False
    assert payload["persisted"] is False


@pytest.mark.contract
def test_rule_api_openapi_and_read_only_registry(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    assert "/api/v1/behavior/rules/evaluate" in schema["paths"]
    assert "/api/v1/behavior/rules" in schema["paths"]
    assert set(schema["paths"]["/api/v1/behavior/rules"]) == {"get"}
    assert client.post("/api/v1/behavior/rules").status_code == 405


@pytest.mark.security
def test_rule_api_rejects_unknown_malformed_and_oversized_input(
    client: TestClient,
) -> None:
    event = file_event(FileAction.CREATE)
    body = {
        "batch": {"events": [event.model_dump(mode="json")]},
        "rule_ids": ["BR-FILE-999"],
    }
    assert client.post("/api/v1/behavior/rules/evaluate", json=body).status_code == 422
    body["rule_ids"] = ["not-code"]
    assert client.post("/api/v1/behavior/rules/evaluate", json=body).status_code == 422
    body["rule"] = "__import__('os').system('whoami')"
    assert client.post("/api/v1/behavior/rules/evaluate", json=body).status_code == 422
    assert (
        client.post(
            "/api/v1/behavior/rules/evaluate",
            content=b"{}",
            headers={"Content-Length": "600000", "Content-Type": "application/json"},
        ).status_code
        == 413
    )


@pytest.mark.integration
def test_rule_api_sanitizes_limits_and_unexpected_failures(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    event = file_event(FileAction.CREATE)
    body = {
        "batch": {"events": [event.model_dump(mode="json")]},
        "rule_ids": ["BR-FILE-001"],
    }

    def limited(*args: object, **kwargs: object) -> None:
        raise RuleEvaluationLimitError("sensitive limit")

    monkeypatch.setattr("app.api.v1.routes.behavior_rules.engine.evaluate", limited)
    response = client.post("/api/v1/behavior/rules/evaluate", json=body)
    assert response.status_code == 503 and "sensitive" not in response.text

    def broken(*args: object, **kwargs: object) -> None:
        raise RuntimeError("sensitive internal detail")

    monkeypatch.setattr("app.api.v1.routes.behavior_rules.engine.evaluate", broken)
    response = client.post("/api/v1/behavior/rules/evaluate", json=body)
    assert response.status_code == 500 and "sensitive" not in response.text
