from __future__ import annotations

import json
from collections import Counter
from uuid import UUID

from app.schemas.behavior import (
    MAX_BATCH_BYTES,
    ConfigurationEvent,
    EventBatch,
    EventValidationIssue,
    EventValidationResult,
    FileAction,
    FileEvent,
    NetworkAction,
    NetworkEvent,
    ProcessAction,
    ProcessEvent,
    ValidationSeverity,
)

LIMITATIONS = (
    "Validation checks declared structure and within-batch consistency only.",
    "A valid event is not evidence of malicious activity, compromise, or ATT&CK technique execution.",
    "Process relationships are not inferred from PID equality alone.",
)


def _issue(
    code: str,
    message: str,
    *event_ids: UUID,
    severity: ValidationSeverity = ValidationSeverity.ERROR,
) -> EventValidationIssue:
    return EventValidationIssue(
        code=code, severity=severity, message=message, event_ids=event_ids
    )


def validate_event_batch(batch: EventBatch) -> EventValidationResult:
    events = batch.events
    issues: list[EventValidationIssue] = []
    encoded = json.dumps(
        batch.model_dump(mode="json"), ensure_ascii=False, separators=(",", ":")
    ).encode()
    if len(encoded) > MAX_BATCH_BYTES:
        issues.append(
            _issue("BATCH_SIZE_EXCEEDED", "Serialized batch exceeds the byte limit.")
        )

    counts = Counter(event.event_id for event in events)
    for event_id, count in counts.items():
        if count > 1:
            issues.append(
                _issue(
                    "DUPLICATE_EVENT_ID",
                    "The same event identity appears more than once.",
                    event_id,
                )
            )

    for previous, current in zip(events, events[1:], strict=False):
        if current.timestamp < previous.timestamp:
            issues.append(
                _issue(
                    "EVENTS_OUT_OF_ORDER",
                    "Event order does not follow ascending event time.",
                    previous.event_id,
                    current.event_id,
                )
            )

    process_hosts: dict[UUID, tuple[str, UUID]] = {}
    starts: dict[UUID, ProcessEvent] = {}
    terminations: set[UUID] = set()
    file_state: set[tuple[str, str]] = set()
    attempted_connections: set[tuple[object, ...]] = set()
    established_connections: set[tuple[object, ...]] = set()

    for event in events:
        process = event.process if hasattr(event, "process") else None
        if process is not None:
            known = process_hosts.get(process.process_instance_id)
            if known is not None and known[0] != event.host_id:
                issues.append(
                    _issue(
                        "PROCESS_HOST_CONFLICT",
                        "A process instance is declared on multiple hosts.",
                        known[1],
                        event.event_id,
                    )
                )
            else:
                process_hosts[process.process_instance_id] = (
                    event.host_id,
                    event.event_id,
                )

        if isinstance(event, ProcessEvent):
            identity = event.process.process_instance_id
            if event.parent_process is not None:
                parent = event.parent_process
                if parent.started_at >= event.process.started_at:
                    issues.append(
                        _issue(
                            "INCONSISTENT_PROCESS_PARENT",
                            "Parent process identity does not predate the child.",
                            event.event_id,
                        )
                    )
                known_parent = process_hosts.get(parent.process_instance_id)
                if known_parent is not None and known_parent[0] != event.host_id:
                    issues.append(
                        _issue(
                            "PROCESS_PARENT_HOST_CONFLICT",
                            "Parent and child process identities belong to different hosts.",
                            known_parent[1],
                            event.event_id,
                        )
                    )
            if event.action is ProcessAction.START:
                prior = starts.get(identity)
                if prior is not None:
                    issues.append(
                        _issue(
                            "DUPLICATE_PROCESS_START",
                            "A process instance has multiple start declarations.",
                            prior.event_id,
                            event.event_id,
                        )
                    )
                starts[identity] = event
            else:
                start = starts.get(identity)
                if start is None or start.host_id != event.host_id:
                    issues.append(
                        _issue(
                            "TERMINATION_WITHOUT_START",
                            "Process termination has no matching start on the same host.",
                            event.event_id,
                        )
                    )
                elif event.timestamp < start.timestamp:
                    issues.append(
                        _issue(
                            "PROCESS_TIME_CONTRADICTION",
                            "Process termination precedes its start event.",
                            start.event_id,
                            event.event_id,
                        )
                    )
                terminations.add(identity)

        elif isinstance(event, FileEvent):
            file_key = (event.host_id, event.file_path)
            if event.action is FileAction.CREATE:
                file_state.add(file_key)
            elif event.action is FileAction.MODIFY and file_key not in file_state:
                issues.append(
                    _issue(
                        "FILE_MODIFY_WITHOUT_CREATE",
                        "No matching file creation exists earlier in this batch.",
                        event.event_id,
                        severity=ValidationSeverity.WARNING,
                    )
                )
            elif event.action is FileAction.DELETE:
                file_state.discard(file_key)
            elif event.destination_path is not None:
                file_state.discard(file_key)
                file_state.add((event.host_id, event.destination_path))

        elif isinstance(event, NetworkEvent):
            network_key = (
                event.host_id,
                str(event.local_ip),
                event.local_port,
                str(event.remote_ip),
                event.remote_port,
                event.protocol,
                event.process.process_instance_id if event.process else None,
            )
            if event.action is NetworkAction.ATTEMPTED:
                attempted_connections.add(network_key)
            elif event.action is NetworkAction.ESTABLISHED:
                if network_key not in attempted_connections:
                    issues.append(
                        _issue(
                            "ESTABLISHED_WITHOUT_ATTEMPT",
                            "Established state has no earlier attempt in this batch.",
                            event.event_id,
                        )
                    )
                established_connections.add(network_key)
            elif network_key not in established_connections:
                issues.append(
                    _issue(
                        "CLOSED_WITHOUT_ESTABLISHED",
                        "Closed state has no earlier established state in this batch.",
                        event.event_id,
                    )
                )

        elif isinstance(event, ConfigurationEvent):
            # Configuration records are descriptive only; validation performs
            # no registry, service, task, or startup operation.
            continue

    for identity, start in starts.items():
        if identity not in terminations:
            issues.append(
                _issue(
                    "PROCESS_LIFECYCLE_INCOMPLETE",
                    "Process start has no matching termination in this batch.",
                    start.event_id,
                    severity=ValidationSeverity.WARNING,
                )
            )

    return EventValidationResult(
        valid=not any(issue.severity is ValidationSeverity.ERROR for issue in issues),
        event_count=len(events),
        issues=tuple(issues),
        limitations=LIMITATIONS,
    )
