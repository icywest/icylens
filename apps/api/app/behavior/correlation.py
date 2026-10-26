from __future__ import annotations

import json
import time
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Sequence
from datetime import datetime, timedelta
from typing import TypeAlias
from uuid import UUID

from app.behavior.correlation_evidence import evidence, relationship_id, sequence_id
from app.behavior.correlation_identity import (
    declared_connection_key,
    declared_file_keys,
    parent_key,
    process_key,
)
from app.behavior.correlation_policy import assess_window, resolve_processing_time
from app.behavior.correlation_rules import event_delta_seconds, windowed_runs
from app.behavior.validation import validate_event_batch
from app.schemas.behavior import (
    EventUnion,
    EventValidationResult,
    FileEvent,
    NetworkEvent,
    ProcessAction,
    ProcessEvent,
)
from app.schemas.behavior_correlation import (
    CORRELATION_DEADLINE_SECONDS,
    MAX_CORRELATION_EDGES,
    MAX_CORRELATION_ISSUES,
    MAX_CORRELATION_OUTPUT_BYTES,
    MAX_EVENTS_PER_SEQUENCE,
    MAX_RELATIONSHIPS_PER_EVENT,
    MAX_TEMPORAL_SEQUENCES,
    CorrelationIssue,
    CorrelationIssueSeverity,
    CorrelationSummary,
    EventRelationship,
    RelationshipConfidence,
    RelationshipState,
    RelationshipType,
    TemporalCorrelationRequest,
    TemporalCorrelationResult,
    TemporalEventNode,
    TemporalSequence,
)

Clock: TypeAlias = Callable[[], float]


class TemporalCorrelationLimitError(RuntimeError):
    pass


def _serialized_event(event: EventUnion) -> str:
    return json.dumps(
        event.model_dump(mode="json"),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _canonical_events(events: Sequence[EventUnion]) -> tuple[EventUnion, ...]:
    by_id: dict[UUID, EventUnion] = {}
    for event in events:
        current = by_id.get(event.event_id)
        if current is None or _serialized_event(event) < _serialized_event(current):
            by_id[event.event_id] = event
    return tuple(
        sorted(by_id.values(), key=lambda item: (item.timestamp, item.event_id))
    )


class TemporalCorrelationEngine:
    def __init__(self, *, clock: Clock = time.monotonic) -> None:
        self._clock = clock

    def correlate(
        self,
        request: TemporalCorrelationRequest,
        *,
        batch_validation: EventValidationResult | None = None,
    ) -> TemporalCorrelationResult:
        started = self._clock()
        policy = request.policy
        submitted = request.batch.events
        events = _canonical_events(submitted)
        processing_time, processing_policy = resolve_processing_time(policy, events)
        issues: list[CorrelationIssue] = []

        def check_deadline() -> None:
            if self._clock() - started > CORRELATION_DEADLINE_SECONDS:
                raise TemporalCorrelationLimitError(
                    "Temporal correlation deadline exceeded"
                )

        def add_issue(
            code: str,
            message: str,
            event_ids: Iterable[UUID] = (),
            severity: CorrelationIssueSeverity = CorrelationIssueSeverity.WARNING,
        ) -> None:
            bounded_event_ids = tuple(sorted(set(event_ids)))[:16]
            item = CorrelationIssue(
                code=code,
                severity=severity,
                message=message,
                event_ids=bounded_event_ids,
            )
            if item not in issues and len(issues) < MAX_CORRELATION_ISSUES:
                issues.append(item)

        counts = Counter(event.event_id for event in submitted)
        for event_id, count in sorted(counts.items()):
            if count > 1:
                variants = {
                    _serialized_event(event)
                    for event in submitted
                    if event.event_id == event_id
                }
                add_issue(
                    "DUPLICATE_EVENT_ID",
                    (
                        "One event identity has conflicting declarations."
                        if len(variants) > 1
                        else "One event identity was submitted more than once."
                    ),
                    (event_id,),
                    (
                        CorrelationIssueSeverity.ERROR
                        if len(variants) > 1
                        else CorrelationIssueSeverity.WARNING
                    ),
                )

        input_was_out_of_order = any(
            current.timestamp < previous.timestamp
            for previous, current in zip(submitted, submitted[1:], strict=False)
        )
        if input_was_out_of_order:
            add_issue(
                "INPUT_ORDER_NOT_TEMPORAL_ORDER",
                "Submitted array order differs from canonical event-time order.",
            )

        by_timestamp: dict[datetime, list[UUID]] = defaultdict(list)
        for event in events:
            check_deadline()
            by_timestamp[event.timestamp].append(event.event_id)
            if event.timestamp > processing_time + timedelta(
                seconds=policy.future_tolerance_seconds
            ):
                add_issue(
                    "EVENT_TIME_IN_FUTURE",
                    "Event time exceeds the configured future tolerance.",
                    (event.event_id,),
                )
            if (
                event.provenance.observed_at - event.timestamp
            ).total_seconds() > policy.clock_skew_seconds:
                add_issue(
                    "EVENT_OBSERVATION_GAP",
                    "Event and observation times exceed the clock-skew threshold.",
                    (event.event_id,),
                )
            if (
                event.provenance.received_at - event.provenance.observed_at
            ).total_seconds() > policy.clock_skew_seconds:
                add_issue(
                    "OBSERVATION_RECEIPT_GAP",
                    "Observation and receipt times exceed the clock-skew threshold.",
                    (event.event_id,),
                )
            if processing_time < event.provenance.received_at:
                add_issue(
                    "PROCESSING_TIME_CONTRADICTION",
                    "Processing time precedes a declared receipt time.",
                    (event.event_id,),
                    CorrelationIssueSeverity.ERROR,
                )

        equal_groups = 0
        for _timestamp, timestamp_event_ids in sorted(by_timestamp.items()):
            if len(timestamp_event_ids) > 1:
                equal_groups += 1
                add_issue(
                    "EQUAL_EVENT_TIMES",
                    "Equal event times have no inferred temporal order; UUID order is presentation only.",
                    timestamp_event_ids,
                )

        relationships: list[EventRelationship] = []
        relation_keys: set[tuple[RelationshipType, UUID, UUID]] = set()
        incident: Counter[UUID] = Counter()
        relationships_truncated = False

        def add_relationship(
            relationship_type: RelationshipType,
            source: EventUnion,
            target: EventUnion,
            confidence: RelationshipConfidence,
            state: RelationshipState,
            criterion: str,
            facts: tuple[str, ...],
            limitations: tuple[str, ...] = (),
        ) -> None:
            nonlocal relationships_truncated
            check_deadline()
            key = (relationship_type, source.event_id, target.event_id)
            if key in relation_keys or source.event_id == target.event_id:
                return
            if (
                len(relationships) >= MAX_CORRELATION_EDGES
                or incident[source.event_id] >= MAX_RELATIONSHIPS_PER_EVENT
                or incident[target.event_id] >= MAX_RELATIONSHIPS_PER_EVENT
            ):
                relationships_truncated = True
                return
            delta = event_delta_seconds(source, target)
            absolute_delta = abs(delta)
            assessment = assess_window(delta, policy)
            relationships.append(
                EventRelationship(
                    relationship_id=relationship_id(
                        relationship_type, source.event_id, target.event_id
                    ),
                    relationship_type=relationship_type,
                    source_event_id=source.event_id,
                    target_event_id=target.event_id,
                    confidence=confidence,
                    state=state,
                    window_assessment=assessment,
                    event_time_delta_seconds=absolute_delta,
                    evidence=evidence(criterion, *facts),
                    limitations=limitations,
                )
            )
            relation_keys.add(key)
            incident[source.event_id] += 1
            incident[target.event_id] += 1

        # Temporal adjacency is factual only. Equal timestamps are deliberately
        # not linked and UUID tie-breaking is never treated as chronology.
        for source, target in zip(events, events[1:], strict=False):
            if source.timestamp < target.timestamp:
                add_relationship(
                    RelationshipType.PRECEDES,
                    source,
                    target,
                    RelationshipConfidence.STRONG,
                    RelationshipState.ESTABLISHED,
                    "event_time_order",
                    ("source_event_time_before_target=true",),
                    ("Temporal precedence is not evidence of causality.",),
                )
                if (
                    source.host_id == target.host_id
                    and event_delta_seconds(source, target)
                    <= policy.time_window_seconds
                ):
                    add_relationship(
                        RelationshipType.WITHIN_TIME_WINDOW,
                        source,
                        target,
                        RelationshipConfidence.INDETERMINATE,
                        RelationshipState.PLAUSIBLE_UNVERIFIED,
                        "bounded_time_proximity",
                        ("same_declared_host=true", "within_configured_window=true"),
                        (
                            "Time proximity and host equality do not establish activity identity or causality.",
                        ),
                    )

        process_groups: dict[tuple[str, UUID], list[EventUnion]] = defaultdict(list)
        process_hosts: dict[UUID, dict[str, list[UUID]]] = defaultdict(
            lambda: defaultdict(list)
        )
        pid_groups: dict[tuple[str, int], dict[UUID, list[UUID]]] = defaultdict(
            lambda: defaultdict(list)
        )
        for event in events:
            key = process_key(event)
            process = event.process if hasattr(event, "process") else None
            if key is not None and process is not None:
                process_groups[key].append(event)
                process_hosts[process.process_instance_id][event.host_id].append(
                    event.event_id
                )
                pid_groups[(event.host_id, process.pid)][
                    process.process_instance_id
                ].append(event.event_id)

        for _identity, hosts in sorted(process_hosts.items(), key=lambda item: item[0]):
            if len(hosts) > 1:
                add_issue(
                    "PROCESS_INSTANCE_HOST_CONFLICT",
                    "One process-instance identity is declared on multiple hosts; no cross-host identity edge was created.",
                    (event_id for values in hosts.values() for event_id in values),
                    CorrelationIssueSeverity.ERROR,
                )
        for (_, _), identities in sorted(pid_groups.items()):
            if len(identities) > 1:
                add_issue(
                    "PID_REUSE_NOT_IDENTITY",
                    "The same PID names multiple process instances; PID equality was not correlated.",
                    (event_id for values in identities.values() for event_id in values),
                )

        sequence_specs: list[
            tuple[
                RelationshipType,
                tuple[EventUnion, ...],
                RelationshipConfidence,
                RelationshipState,
                tuple[str, ...],
            ]
        ] = []
        for _process_key, process_members in sorted(
            process_groups.items(), key=lambda item: item[0]
        ):
            ordered_process_events = tuple(
                sorted(
                    process_members, key=lambda item: (item.timestamp, item.event_id)
                )
            )
            for source, target in zip(
                ordered_process_events, ordered_process_events[1:], strict=False
            ):
                if event_delta_seconds(source, target) <= policy.time_window_seconds:
                    add_relationship(
                        RelationshipType.SAME_PROCESS_INSTANCE,
                        source,
                        target,
                        RelationshipConfidence.STRONG,
                        RelationshipState.ESTABLISHED,
                        "explicit_process_instance",
                        (
                            "process_instance_id_match=true",
                            "same_declared_host=true",
                        ),
                    )
                else:
                    add_issue(
                        "PROCESS_EVENTS_OUTSIDE_WINDOW",
                        "Matching process-instance declarations exceed the correlation window.",
                        (source.event_id, target.event_id),
                    )
            lifecycle_events = tuple(
                event
                for event in ordered_process_events
                if isinstance(event, ProcessEvent)
            )
            lifecycle_starts = tuple(
                event
                for event in lifecycle_events
                if event.action is ProcessAction.START
            )
            lifecycle_terminations = tuple(
                event
                for event in lifecycle_events
                if event.action is ProcessAction.TERMINATE
            )
            if len(lifecycle_starts) > 1:
                add_issue(
                    "MULTIPLE_PROCESS_STARTS",
                    "A process instance has multiple declared start events.",
                    (event.event_id for event in lifecycle_starts),
                    CorrelationIssueSeverity.ERROR,
                )
            if len(lifecycle_terminations) > 1:
                add_issue(
                    "MULTIPLE_PROCESS_TERMINATIONS",
                    "A process instance has multiple declared termination events.",
                    (event.event_id for event in lifecycle_terminations),
                    CorrelationIssueSeverity.ERROR,
                )
            if lifecycle_starts and any(
                termination.timestamp < lifecycle_starts[0].timestamp
                for termination in lifecycle_terminations
            ):
                add_issue(
                    "PROCESS_LIFECYCLE_CONTRADICTION",
                    "A process termination event precedes its declared start event.",
                    (event.event_id for event in lifecycle_events),
                    CorrelationIssueSeverity.ERROR,
                )
            if lifecycle_terminations and not lifecycle_starts:
                add_issue(
                    "PROCESS_START_NOT_PRESENT",
                    "A termination has no start event in this batch; absence does not prove it never occurred.",
                    (event.event_id for event in lifecycle_terminations),
                )
            for run in windowed_runs(
                ordered_process_events, policy.time_window_seconds
            ):
                sequence_specs.append(
                    (
                        RelationshipType.SAME_PROCESS_INSTANCE,
                        run,
                        RelationshipConfidence.STRONG,
                        RelationshipState.ESTABLISHED,
                        ("Process identity is explicit and host-scoped.",),
                    )
                )

        starts: dict[tuple[str, UUID], list[ProcessEvent]] = defaultdict(list)
        starts_by_identity: dict[UUID, list[ProcessEvent]] = defaultdict(list)
        for event in events:
            if isinstance(event, ProcessEvent) and event.action is ProcessAction.START:
                key = process_key(event)
                if key is not None:
                    starts[key].append(event)
                    starts_by_identity[event.process.process_instance_id].append(event)
        for child in (event for event in events if isinstance(event, ProcessEvent)):
            key = parent_key(child)
            if key is None:
                continue
            candidates = starts.get(key, [])
            if len(candidates) != 1:
                other_hosts = starts_by_identity.get(key[1], [])
                if other_hosts and not candidates:
                    add_issue(
                        "PARENT_HOST_CONFLICT",
                        "The declared parent process exists only on a different host.",
                        (child.event_id, *(item.event_id for item in other_hosts)),
                        CorrelationIssueSeverity.ERROR,
                    )
                    continue
                add_issue(
                    "PARENT_EVENT_IDENTITY_INSUFFICIENT",
                    "An explicit parent identity has no unique start event in this batch.",
                    (child.event_id, *(item.event_id for item in candidates)),
                )
                continue
            parent = candidates[0]
            if parent.timestamp > child.timestamp:
                add_issue(
                    "PARENT_TIME_CONTRADICTION",
                    "The declared parent start event follows the child event.",
                    (parent.event_id, child.event_id),
                    CorrelationIssueSeverity.ERROR,
                )
            elif event_delta_seconds(parent, child) <= policy.time_window_seconds:
                add_relationship(
                    RelationshipType.PARENT_PROCESS,
                    parent,
                    child,
                    RelationshipConfidence.STRONG,
                    RelationshipState.ESTABLISHED,
                    "explicit_parent_process",
                    ("parent_process_instance_match=true", "same_declared_host=true"),
                    (
                        "The declared parent relationship does not prove malicious causality.",
                    ),
                )
            else:
                add_issue(
                    "PARENT_EVENTS_OUTSIDE_WINDOW",
                    "Declared parent and child events exceed the correlation window.",
                    (parent.event_id, child.event_id),
                )

        file_groups: dict[tuple[str, str], list[FileEvent]] = defaultdict(list)
        for event in events:
            if isinstance(event, FileEvent):
                for file_key in declared_file_keys(event):
                    file_groups[file_key].append(event)
        for _, file_members in sorted(file_groups.items()):
            unique_file_events = {item.event_id: item for item in file_members}
            ordered_file_events = tuple(
                sorted(
                    unique_file_events.values(),
                    key=lambda item: (item.timestamp, item.event_id),
                )
            )
            for source, target in zip(
                ordered_file_events, ordered_file_events[1:], strict=False
            ):
                if event_delta_seconds(source, target) <= policy.time_window_seconds:
                    add_relationship(
                        RelationshipType.SAME_DECLARED_FILE,
                        source,
                        target,
                        RelationshipConfidence.WEAK,
                        RelationshipState.PLAUSIBLE_UNVERIFIED,
                        "declared_file_path",
                        ("same_declared_host=true", "declared_path_match=true"),
                        (
                            "Path equality is not persistent physical-file identity; rename continuity is declared only.",
                        ),
                    )
            for run in windowed_runs(ordered_file_events, policy.time_window_seconds):
                sequence_specs.append(
                    (
                        RelationshipType.SAME_DECLARED_FILE,
                        run,
                        RelationshipConfidence.WEAK,
                        RelationshipState.PLAUSIBLE_UNVERIFIED,
                        ("No persistent file identifier is present in schema 1.0.0.",),
                    )
                )

        connection_groups: dict[tuple[object, ...], list[NetworkEvent]] = defaultdict(
            list
        )
        for event in events:
            if not isinstance(event, NetworkEvent):
                continue
            connection_key = declared_connection_key(event)
            if connection_key is None:
                add_issue(
                    "CONNECTION_IDENTITY_INSUFFICIENT",
                    "A network event lacks explicit process identity and was not merged by endpoint tuple alone.",
                    (event.event_id,),
                )
            else:
                connection_groups[connection_key].append(event)
        for _, connection_members in sorted(connection_groups.items()):
            ordered_connection_events = tuple(
                sorted(
                    connection_members,
                    key=lambda item: (item.timestamp, item.event_id),
                )
            )
            for source, target in zip(
                ordered_connection_events,
                ordered_connection_events[1:],
                strict=False,
            ):
                if event_delta_seconds(source, target) <= policy.time_window_seconds:
                    add_relationship(
                        RelationshipType.SAME_DECLARED_CONNECTION,
                        source,
                        target,
                        RelationshipConfidence.WEAK,
                        RelationshipState.PLAUSIBLE_UNVERIFIED,
                        "declared_network_tuple",
                        (
                            "endpoint_tuple_match=true",
                            "process_instance_id_match=true",
                            "same_declared_host=true",
                        ),
                        (
                            "Schema 1.0.0 has no persistent connection ID; endpoint tuples can be reused.",
                        ),
                    )
                else:
                    add_issue(
                        "CONNECTION_EVENTS_OUTSIDE_WINDOW",
                        "Matching connection declarations exceed the correlation window.",
                        (source.event_id, target.event_id),
                    )
            for run in windowed_runs(
                ordered_connection_events, policy.time_window_seconds
            ):
                sequence_specs.append(
                    (
                        RelationshipType.SAME_DECLARED_CONNECTION,
                        run,
                        RelationshipConfidence.WEAK,
                        RelationshipState.PLAUSIBLE_UNVERIFIED,
                        (
                            "No persistent connection identifier is present in schema 1.0.0.",
                        ),
                    )
                )

        if relationships_truncated:
            add_issue(
                "RELATIONSHIP_LIMIT_REACHED",
                "One or more relationship candidates were omitted by graph limits.",
            )

        sequences: list[TemporalSequence] = []
        sequences_truncated = False
        for relation_type, members, confidence, state, limitations in sorted(
            sequence_specs,
            key=lambda item: (
                item[0].value,
                tuple(str(event.event_id) for event in item[1]),
            ),
        ):
            check_deadline()
            if len(sequences) >= MAX_TEMPORAL_SEQUENCES:
                sequences_truncated = True
                break
            bounded_members = members[:MAX_EVENTS_PER_SEQUENCE]
            if len(bounded_members) < len(members):
                sequences_truncated = True
            sequence_event_ids = tuple(event.event_id for event in bounded_members)
            sequences.append(
                TemporalSequence(
                    sequence_id=sequence_id(relation_type, sequence_event_ids),
                    relationship_type=relation_type,
                    event_ids=sequence_event_ids,
                    started_at=bounded_members[0].timestamp,
                    ended_at=bounded_members[-1].timestamp,
                    confidence=confidence,
                    state=state,
                    limitations=limitations,
                )
            )
        if sequences_truncated:
            add_issue(
                "SEQUENCE_LIMIT_REACHED",
                "One or more sequence candidates or members were omitted by limits.",
            )

        order = {event.event_id: index for index, event in enumerate(events)}
        relationships.sort(
            key=lambda item: (
                order[item.source_event_id],
                order[item.target_event_id],
                item.relationship_type.value,
            )
        )
        issues.sort(key=lambda item: (item.code, tuple(map(str, item.event_ids))))
        nodes = tuple(
            TemporalEventNode(
                event_id=event.event_id,
                event_type=event.event_type,
                event_time=event.timestamp,
                observed_at=event.provenance.observed_at,
                received_at=event.provenance.received_at,
                canonical_order=index,
            )
            for index, event in enumerate(events)
        )
        confidence_counts = Counter(item.confidence for item in relationships)
        result = TemporalCorrelationResult(
            batch_validation=batch_validation or validate_event_batch(request.batch),
            policy=policy,
            processing_time=processing_time,
            generated_at=processing_time,
            processing_time_policy=processing_policy,
            nodes=nodes,
            relationships=tuple(relationships),
            sequences=tuple(sequences),
            issues=tuple(issues),
            summary=CorrelationSummary(
                submitted_event_count=len(submitted),
                unique_event_count=len(events),
                relationship_count=len(relationships),
                sequence_count=len(sequences),
                strong_relationships=confidence_counts[RelationshipConfidence.STRONG],
                weak_relationships=confidence_counts[RelationshipConfidence.WEAK],
                indeterminate_relationships=confidence_counts[
                    RelationshipConfidence.INDETERMINATE
                ],
                issue_count=len(issues),
                input_was_out_of_order=input_was_out_of_order,
                equal_timestamp_groups=equal_groups,
                relationships_truncated=relationships_truncated,
                sequences_truncated=sequences_truncated,
            ),
            limitations=(
                "Relationships use only declarations in this bounded request; missing events do not prove non-occurrence.",
                "Temporal precedence, proximity, and shared identifiers do not establish causality or maliciousness.",
                "Host clocks are not corrected or assumed synchronized; ambiguity remains explicit.",
                "Rule findings, ATT&CK mappings, malware labels, and persistent state are outside this operation.",
            ),
        )
        encoded = json.dumps(
            result.model_dump(mode="json"), ensure_ascii=False, separators=(",", ":")
        ).encode()
        if len(encoded) > MAX_CORRELATION_OUTPUT_BYTES:
            raise TemporalCorrelationLimitError(
                "Serialized temporal correlation output exceeds the byte limit"
            )
        return result
