from __future__ import annotations

import json
import time
from collections.abc import Callable, Sequence
from typing import cast
from uuid import UUID

from app.behavior.rule_registry import DEFAULT_RULE_REGISTRY, RuleRegistry
from app.behavior.validation import validate_event_batch
from app.schemas.behavior import (
    BehavioralEvent,
    ConfigurationEvent,
    ConfigurationKind,
    EventUnion,
    EventValidationResult,
    FileAction,
    FileEvent,
    NetworkAction,
    NetworkEvent,
    NetworkProtocol,
    ProcessAction,
    ProcessEvent,
)
from app.schemas.behavior_rules import (
    MAX_EVIDENCE_PER_FINDING,
    MAX_FINDINGS_PER_EVALUATION,
    MAX_RULE_OUTPUT_BYTES,
    MAX_RULES_PER_EVALUATION,
    REDACTED_EVIDENCE_VALUE,
    RULE_EVALUATION_DEADLINE_SECONDS,
    BehavioralRule,
    EvidenceField,
    RuleEvaluationRequest,
    RuleEvaluationResult,
    RuleEvaluationSummary,
    RuleEvidence,
    RuleFinding,
    RuleMatchStatus,
)

Clock = Callable[[], float]


class RuleEvaluationLimitError(RuntimeError):
    """Trusted rule evaluation exceeded a deterministic resource bound."""


def _connection_key(event: NetworkEvent) -> tuple[object, ...]:
    return (
        event.host_id,
        str(event.local_ip),
        event.local_port,
        str(event.remote_ip),
        event.remote_port,
        event.protocol,
        event.process.process_instance_id if event.process else None,
    )


def _field(
    name: str, value: str | int | bool | None, *, sensitive: bool = False
) -> EvidenceField:
    if sensitive and value is not None:
        return EvidenceField(
            field=name,
            value=REDACTED_EVIDENCE_VALUE,
            redacted=True,
        )
    if isinstance(value, str) and len(value) > 256:
        return EvidenceField(
            field=name,
            value=REDACTED_EVIDENCE_VALUE,
            redacted=True,
        )
    return EvidenceField(field=name, value=value, redacted=False)


def _evidence(event: BehavioralEvent) -> RuleEvidence:
    fields = [
        _field("event_type", event.event_type),
        _field("timestamp", event.timestamp.isoformat()),
        _field("host_id", event.host_id, sensitive=True),
    ]
    if isinstance(event, ProcessEvent):
        fields.extend(
            (
                _field("action", event.action.value),
                _field("process_instance_id", str(event.process.process_instance_id)),
                _field("process_started_at", event.process.started_at.isoformat()),
                _field("parent_process_present", event.parent_process is not None),
                _field(
                    "parent_process_instance_id",
                    str(event.parent_process.process_instance_id)
                    if event.parent_process
                    else None,
                ),
                _field(
                    "parent_process_started_at",
                    event.parent_process.started_at.isoformat()
                    if event.parent_process
                    else None,
                ),
                _field("command_line_present", event.command_line is not None),
                _field(
                    "command_line_length",
                    len(event.command_line) if event.command_line else 0,
                    sensitive=event.command_line is not None,
                ),
            )
        )
    elif isinstance(event, FileEvent):
        fields.extend(
            (
                _field("action", event.action.value),
                _field("file_path", event.file_path, sensitive=True),
                _field("destination_path_present", event.destination_path is not None),
                _field("process_present", event.process is not None),
                _field("hashes_present", event.hashes is not None),
            )
        )
    elif isinstance(event, NetworkEvent):
        fields.extend(
            (
                _field("action", event.action.value),
                _field(
                    "local_endpoint",
                    f"{event.local_ip}:{event.local_port}",
                    sensitive=True,
                ),
                _field(
                    "remote_endpoint",
                    f"{event.remote_ip}:{event.remote_port}",
                    sensitive=True,
                ),
                _field("protocol", event.protocol.value),
                _field("process_present", event.process is not None),
            )
        )
    elif isinstance(event, ConfigurationEvent):
        fields.extend(
            (
                _field("action", event.action),
                _field("configuration_kind", event.configuration_kind.value),
                _field("target", event.target, sensitive=True),
                _field("previous_value_present", event.previous_value is not None),
                _field("current_value_present", event.current_value is not None),
            )
        )
    return RuleEvidence(
        event_id=event.event_id,
        source_id=REDACTED_EVIDENCE_VALUE,
        nature=event.provenance.nature,
        fields=tuple(fields),
    )


def _family_events(
    rule: BehavioralRule, events: Sequence[EventUnion]
) -> tuple[BehavioralEvent, ...]:
    expected: type[BehavioralEvent]
    if rule.family.value == "process":
        expected = ProcessEvent
    elif rule.family.value == "file":
        expected = FileEvent
    elif rule.family.value == "network":
        expected = NetworkEvent
    else:
        expected = ConfigurationEvent
    return tuple(event for event in events if isinstance(event, expected))


def _evaluate_process(
    rule_id: str, events: tuple[ProcessEvent, ...], all_events: Sequence[EventUnion]
) -> tuple[RuleMatchStatus, tuple[ProcessEvent, ...]]:
    if rule_id == "BR-PROC-001":
        matches = tuple(
            event
            for event in events
            if event.action is ProcessAction.START and event.parent_process is None
        )
        return (
            RuleMatchStatus.MATCHED if matches else RuleMatchStatus.NOT_MATCHED,
            matches,
        )
    if rule_id == "BR-PROC-002":
        with_parent = tuple(
            event for event in events if event.parent_process is not None
        )
        if not with_parent:
            return RuleMatchStatus.INSUFFICIENT_EVIDENCE, events
        process_hosts: dict[UUID, set[str]] = {}
        for item in all_events:
            process = item.process if hasattr(item, "process") else None
            if process is not None:
                process_hosts.setdefault(process.process_instance_id, set()).add(
                    item.host_id
                )

        def parent_is_inconsistent(event: ProcessEvent) -> bool:
            parent = event.parent_process
            if parent is None:
                return False
            return parent.started_at >= event.process.started_at or any(
                host != event.host_id
                for host in process_hosts.get(parent.process_instance_id, set())
            )

        matches = tuple(event for event in with_parent if parent_is_inconsistent(event))
        return (
            RuleMatchStatus.MATCHED if matches else RuleMatchStatus.NOT_MATCHED,
            matches,
        )
    starts = tuple(event for event in events if event.action is ProcessAction.START)
    if not starts:
        return RuleMatchStatus.NOT_MATCHED, ()
    matches = tuple(event for event in starts if event.command_line is not None)
    if matches:
        return RuleMatchStatus.MATCHED, matches
    return RuleMatchStatus.INSUFFICIENT_EVIDENCE, starts


def _evaluate_file(
    rule_id: str, events: tuple[FileEvent, ...]
) -> tuple[RuleMatchStatus, tuple[FileEvent, ...]]:
    if rule_id == "BR-FILE-001":
        created: set[tuple[str, str]] = set()
        matches: list[FileEvent] = []
        for event in events:
            key = (event.host_id, event.file_path)
            if event.action is FileAction.CREATE:
                created.add(key)
            elif event.action is FileAction.MODIFY and key in created:
                matches.append(event)
        result = tuple(matches)
    elif rule_id == "BR-FILE-002":
        result = tuple(
            event
            for event in events
            if event.action is FileAction.RENAME
            and (event.process is None or event.hashes is None)
        )
    else:
        result = tuple(event for event in events if event.process is None)
    return (RuleMatchStatus.MATCHED if result else RuleMatchStatus.NOT_MATCHED, result)


def _evaluate_network(
    rule_id: str, events: tuple[NetworkEvent, ...]
) -> tuple[RuleMatchStatus, tuple[NetworkEvent, ...]]:
    if rule_id == "BR-NET-001":
        pending: dict[tuple[object, ...], NetworkEvent] = {}
        for event in events:
            key = _connection_key(event)
            if event.action is NetworkAction.ATTEMPTED:
                pending[key] = event
            elif event.action in {NetworkAction.ESTABLISHED, NetworkAction.CLOSED}:
                pending.pop(key, None)
        result = tuple(pending.values())
    elif rule_id == "BR-NET-002":
        result = tuple(
            event
            for event in events
            if event.action is NetworkAction.ESTABLISHED and event.process is None
        )
    else:
        result = tuple(
            event
            for event in events
            if event.protocol is NetworkProtocol.TCP and event.remote_port == 443
        )
    return (RuleMatchStatus.MATCHED if result else RuleMatchStatus.NOT_MATCHED, result)


def _evaluate_configuration(
    rule_id: str, events: tuple[ConfigurationEvent, ...]
) -> tuple[RuleMatchStatus, tuple[ConfigurationEvent, ...]]:
    if rule_id == "BR-CONF-001":
        result = events
    elif rule_id == "BR-CONF-002":
        result = tuple(
            event
            for event in events
            if event.configuration_kind is ConfigurationKind.SCHEDULED_TASK
            and event.previous_value is None
            and event.current_value is not None
        )
    else:
        result = tuple(
            event
            for event in events
            if event.configuration_kind is ConfigurationKind.SERVICE
            and event.previous_value is not None
            and event.current_value is not None
        )
    return (RuleMatchStatus.MATCHED if result else RuleMatchStatus.NOT_MATCHED, result)


def _evaluate_rule(
    rule: BehavioralRule, events: Sequence[EventUnion]
) -> tuple[RuleMatchStatus, tuple[BehavioralEvent, ...]]:
    applicable = _family_events(rule, events)
    if not rule.enabled or not applicable:
        return RuleMatchStatus.NOT_APPLICABLE, ()
    if rule.family.value == "process":
        return _evaluate_process(
            rule.rule_id, cast(tuple[ProcessEvent, ...], applicable), events
        )
    if rule.family.value == "file":
        return _evaluate_file(rule.rule_id, cast(tuple[FileEvent, ...], applicable))
    if rule.family.value == "network":
        return _evaluate_network(
            rule.rule_id, cast(tuple[NetworkEvent, ...], applicable)
        )
    return _evaluate_configuration(
        rule.rule_id, cast(tuple[ConfigurationEvent, ...], applicable)
    )


class BehavioralRuleEngine:
    def __init__(
        self,
        registry: RuleRegistry = DEFAULT_RULE_REGISTRY,
        *,
        clock: Clock = time.monotonic,
    ) -> None:
        self._registry = registry
        self._clock = clock

    def evaluate(
        self,
        request: RuleEvaluationRequest,
        *,
        batch_validation: EventValidationResult | None = None,
    ) -> RuleEvaluationResult:
        rules = self._registry.select(request.rule_ids)
        if len(rules) > MAX_RULES_PER_EVALUATION:
            raise RuleEvaluationLimitError("Rule count exceeds the evaluation limit")
        started = self._clock()
        findings: list[RuleFinding] = []
        for rule in rules:
            if self._clock() - started > RULE_EVALUATION_DEADLINE_SECONDS:
                raise RuleEvaluationLimitError("Rule evaluation deadline exceeded")
            status, candidates = _evaluate_rule(rule, request.batch.events)
            unique: dict[UUID, BehavioralEvent] = {}
            for event in candidates:
                unique.setdefault(event.event_id, event)
            bounded = tuple(unique.values())[:MAX_EVIDENCE_PER_FINDING]
            limitations = list(rule.limitations)
            if len(unique) > len(bounded):
                limitations.append("Evidence was truncated at the per-finding limit.")
            evidence = tuple(_evidence(event) for event in bounded)
            findings.append(
                RuleFinding(
                    rule_id=rule.rule_id,
                    rule_version=rule.version,
                    rule_name=rule.name,
                    family=rule.family,
                    result=status,
                    event_ids=tuple(item.event_id for item in evidence),
                    satisfied_conditions=(
                        tuple(condition.description for condition in rule.conditions)
                        if status is RuleMatchStatus.MATCHED
                        else ()
                    ),
                    evidence=evidence,
                    event_sources=tuple(
                        dict.fromkeys(item.source_id for item in evidence)
                    ),
                    event_natures=tuple(
                        dict.fromkeys(item.nature for item in evidence)
                    ),
                    limitations=tuple(limitations),
                )
            )
            if len(findings) > MAX_FINDINGS_PER_EVALUATION:
                raise RuleEvaluationLimitError("Finding count exceeds the output limit")
        counts = {status: 0 for status in RuleMatchStatus}
        for finding in findings:
            counts[finding.result] += 1
        result = RuleEvaluationResult(
            batch_validation=batch_validation or validate_event_batch(request.batch),
            findings=tuple(findings),
            summary=RuleEvaluationSummary(
                evaluated_rules=len(findings),
                matched=counts[RuleMatchStatus.MATCHED],
                not_matched=counts[RuleMatchStatus.NOT_MATCHED],
                insufficient_evidence=counts[RuleMatchStatus.INSUFFICIENT_EVIDENCE],
                not_applicable=counts[RuleMatchStatus.NOT_APPLICABLE],
                findings_truncated=False,
            ),
            limitations=(
                "Results describe rule conditions over submitted events, not confirmed attacks.",
                "No malware classification, attribution, or MITRE ATT&CK mapping was performed.",
                "Evaluation uses only facts and ordering available in this request batch.",
            ),
        )
        encoded = json.dumps(
            result.model_dump(mode="json"), ensure_ascii=False, separators=(",", ":")
        ).encode()
        if len(encoded) > MAX_RULE_OUTPUT_BYTES:
            raise RuleEvaluationLimitError(
                "Serialized rule output exceeds the byte limit"
            )
        return result
