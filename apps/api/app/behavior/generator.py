from __future__ import annotations

import random
from datetime import datetime, timedelta
from uuid import NAMESPACE_URL, UUID, uuid5

from app.behavior.validation import validate_event_batch
from app.schemas.behavior import (
    ConfigurationEvent,
    ConfigurationKind,
    EventBatch,
    EventNature,
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
    SyntheticScenario,
    SyntheticScenarioKind,
    SyntheticScenarioMetadata,
    SyntheticScenarioRequest,
)


def _uuid(request: SyntheticScenarioRequest, label: str) -> UUID:
    return uuid5(
        NAMESPACE_URL,
        f"icylens:{request.scenario_id}:{request.scenario_kind}:{request.seed}:{label}",
    )


def _path(request: SyntheticScenarioRequest, name: str) -> str:
    if request.platform.value == "windows":
        return f"C:\\SyntheticLab\\{name}"
    return f"/tmp/icylens-synthetic/{name}"


def generate_scenario(request: SyntheticScenarioRequest) -> SyntheticScenario:
    rng = random.Random(f"{request.seed}:{request.scenario_id}:{request.scenario_kind}")
    host_id = f"synthetic-host-{_uuid(request, 'host').hex[:12]}"
    source = EventSource(
        kind=EventSourceKind.SYNTHETIC_GENERATOR,
        source_id=f"synthetic:{request.scenario_id}",
        producer="iCYLENS deterministic educational generator",
    )
    parent = ProcessIdentity(
        process_instance_id=_uuid(request, "parent"),
        pid=rng.randint(100, 2000),
        started_at=request.start_time - timedelta(minutes=5),
    )
    process = ProcessIdentity(
        process_instance_id=_uuid(request, "process"),
        pid=rng.randint(2001, 30_000),
        started_at=request.start_time,
    )

    def provenance(
        timestamp: datetime, missing: tuple[str, ...] = ()
    ) -> EventProvenance:
        return EventProvenance(
            source_identifier=source.source_id,
            observed_at=timestamp,
            received_at=timestamp + timedelta(milliseconds=25),
            nature=EventNature.SYNTHETIC,
            missing_fields=missing,
            limitations=(
                "Generated offline; no endpoint agent observed this event.",
                "Event content is descriptive and was not executed.",
            ),
        )

    def common(
        index: int, timestamp: datetime, missing: tuple[str, ...] = ()
    ) -> dict[str, object]:
        return {
            "event_id": _uuid(request, f"event:{index}"),
            "timestamp": timestamp,
            "host_id": host_id,
            "source": source,
            "platform": request.platform,
            "synthetic": True,
            "provenance": provenance(timestamp, missing),
            "attributes": {"scenario_id": request.scenario_id, "ordinal": index},
        }

    events: list[ProcessEvent | FileEvent | NetworkEvent | ConfigurationEvent] = []
    for index in range(request.event_count):
        timestamp = request.start_time + timedelta(seconds=index)
        kind = request.scenario_kind
        if kind in {
            SyntheticScenarioKind.NORMAL_PROCESS,
            SyntheticScenarioKind.INCOMPLETE_SEQUENCE,
            SyntheticScenarioKind.INCONSISTENT_PROCESS,
        }:
            pair = index // 2 if kind is SyntheticScenarioKind.NORMAL_PROCESS else index
            event_process = ProcessIdentity(
                process_instance_id=_uuid(request, f"process:{pair}"),
                pid=2001 + pair,
                started_at=(
                    request.start_time + timedelta(seconds=pair * 2)
                    if kind is SyntheticScenarioKind.NORMAL_PROCESS
                    else timestamp
                ),
            )
            process_action = (
                ProcessAction.START
                if kind is not SyntheticScenarioKind.NORMAL_PROCESS or index % 2 == 0
                else ProcessAction.TERMINATE
            )
            inconsistent_parent = ProcessIdentity(
                process_instance_id=parent.process_instance_id,
                pid=parent.pid,
                started_at=event_process.started_at + timedelta(minutes=1),
            )
            events.append(
                ProcessEvent(
                    event_type="process",
                    action=process_action,
                    process=event_process,
                    parent_process=(
                        inconsistent_parent
                        if kind is SyntheticScenarioKind.INCONSISTENT_PROCESS
                        else parent
                    ),
                    executable_path=_path(request, "benign-app"),
                    command_line=f"{_path(request, 'benign-app')} --educational",
                    user_context="synthetic-user",
                    exit_code=(
                        0 if process_action is ProcessAction.TERMINATE else None
                    ),
                    **common(index, timestamp),
                )
            )
        elif kind in {
            SyntheticScenarioKind.FILE_SEQUENCE,
            SyntheticScenarioKind.OUT_OF_ORDER,
            SyntheticScenarioKind.DUPLICATE_EVENTS,
            SyntheticScenarioKind.MISSING_OPTIONAL,
        }:
            if kind is SyntheticScenarioKind.OUT_OF_ORDER:
                timestamp = request.start_time + timedelta(
                    seconds=request.event_count - index
                )
            missing = (
                ("hashes", "process", "user_context")
                if kind is SyntheticScenarioKind.MISSING_OPTIONAL
                else ()
            )
            event = FileEvent(
                event_type="file",
                action=FileAction.CREATE if index % 2 == 0 else FileAction.MODIFY,
                file_path=_path(
                    request,
                    f"document-{_uuid(request, f'file:{index // 2}').hex[:8]}.txt",
                ),
                destination_path=None,
                hashes=None,
                process=None
                if kind is SyntheticScenarioKind.MISSING_OPTIONAL
                else process,
                **common(index, timestamp, missing),
            )
            events.append(
                events[0]
                if kind is SyntheticScenarioKind.DUPLICATE_EVENTS and events
                else event
            )
        elif kind in {
            SyntheticScenarioKind.NETWORK_SEQUENCE,
            SyntheticScenarioKind.CONTRADICTORY_DATA,
        }:
            pair = index // 2
            ipv6 = pair % 2 == 1
            network_action = (
                NetworkAction.ESTABLISHED
                if kind is SyntheticScenarioKind.CONTRADICTORY_DATA or index % 2
                else NetworkAction.ATTEMPTED
            )
            events.append(
                NetworkEvent(
                    event_type="network",
                    action=network_action,
                    local_ip="2001:db8::10" if ipv6 else "192.0.2.10",
                    local_port=40_000 + pair,
                    remote_ip="2001:db8::20" if ipv6 else "198.51.100.20",
                    remote_port=443,
                    protocol=NetworkProtocol.TCP,
                    process=process,
                    **common(index, timestamp),
                )
            )
        else:
            events.append(
                ConfigurationEvent(
                    event_type="configuration",
                    action="reported_change",
                    configuration_kind=ConfigurationKind.STARTUP,
                    target=f"synthetic-startup-entry-{index}",
                    previous_value="disabled",
                    current_value="enabled",
                    process=process,
                    **common(index, timestamp),
                )
            )

    batch = EventBatch(events=tuple(events))
    metadata = SyntheticScenarioMetadata(
        scenario_id=request.scenario_id,
        scenario_kind=request.scenario_kind,
        seed=request.seed,
        platform=request.platform,
        host_id=host_id,
        start_time=request.start_time,
        generated_at=request.start_time + timedelta(seconds=request.event_count),
        requested_event_count=request.event_count,
    )
    return SyntheticScenario(
        metadata=metadata,
        events=batch.events,
        validation=validate_event_batch(batch),
    )
