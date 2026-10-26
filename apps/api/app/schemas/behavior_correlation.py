from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from app.schemas.behavior import EventBatch, EventValidationResult, _utc
from app.schemas.vulnerability import StrictContract

CORRELATION_SCHEMA_VERSION = "1.0.0"
MAX_CORRELATION_EDGES = 1024
MAX_RELATIONSHIPS_PER_EVENT = 16
MAX_TEMPORAL_SEQUENCES = 128
MAX_EVENTS_PER_SEQUENCE = 64
MAX_EVIDENCE_FACTS = 8
MAX_CORRELATION_ISSUES = 512
MAX_CORRELATION_OUTPUT_BYTES = 512 * 1024
CORRELATION_DEADLINE_SECONDS = 1.0
DEFAULT_TIME_WINDOW_SECONDS = 300
MAX_TIME_WINDOW_SECONDS = 86_400
DEFAULT_CLOCK_SKEW_SECONDS = 60
MAX_CLOCK_SKEW_SECONDS = 86_400
DEFAULT_FUTURE_TOLERANCE_SECONDS = 300
MAX_FUTURE_TOLERANCE_SECONDS = 86_400


class RelationshipType(str, Enum):
    PRECEDES = "precedes"
    FOLLOWS = "follows"
    SAME_PROCESS_INSTANCE = "same_process_instance"
    PARENT_PROCESS = "parent_process"
    SAME_DECLARED_FILE = "same_declared_file"
    SAME_DECLARED_CONNECTION = "same_declared_connection"
    WITHIN_TIME_WINDOW = "within_time_window"


class RelationshipConfidence(str, Enum):
    STRONG = "strong"
    WEAK = "weak"
    INDETERMINATE = "indeterminate"


class RelationshipState(str, Enum):
    ESTABLISHED = "established"
    PLAUSIBLE_UNVERIFIED = "plausible_unverified"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    CONTRADICTORY_EVIDENCE = "contradictory_evidence"
    NOT_RELATED = "not_related"


class WindowAssessment(str, Enum):
    WITHIN = "within"
    OUTSIDE = "outside"
    UNKNOWN = "unknown"
    INSUFFICIENT = "insufficient"


class CorrelationIssueSeverity(str, Enum):
    WARNING = "warning"
    ERROR = "error"


class CorrelationPolicy(StrictContract):
    time_window_seconds: Annotated[int, Field(ge=1, le=MAX_TIME_WINDOW_SECONDS)] = (
        DEFAULT_TIME_WINDOW_SECONDS
    )
    clock_skew_seconds: Annotated[int, Field(ge=0, le=MAX_CLOCK_SKEW_SECONDS)] = (
        DEFAULT_CLOCK_SKEW_SECONDS
    )
    future_tolerance_seconds: Annotated[
        int, Field(ge=0, le=MAX_FUTURE_TOLERANCE_SECONDS)
    ] = DEFAULT_FUTURE_TOLERANCE_SECONDS
    processing_time: datetime | None = None

    @field_validator("processing_time")
    @classmethod
    def normalize_processing_time(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _utc(value)


class RelationshipEvidence(StrictContract):
    criterion: Annotated[str, Field(min_length=1, max_length=64)]
    facts: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=256)], ...],
        Field(min_length=1, max_length=MAX_EVIDENCE_FACTS),
    ]


class EventRelationship(StrictContract):
    relationship_id: UUID
    relationship_type: RelationshipType
    source_event_id: UUID
    target_event_id: UUID
    confidence: RelationshipConfidence
    state: RelationshipState
    window_assessment: WindowAssessment
    event_time_delta_seconds: Annotated[float | None, Field(ge=0)]
    evidence: Annotated[
        tuple[RelationshipEvidence, ...], Field(min_length=1, max_length=8)
    ]
    limitations: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...],
        Field(max_length=8),
    ]
    causal: Literal[False] = False

    @model_validator(mode="after")
    def reject_self_relationship(self) -> Self:
        if self.source_event_id == self.target_event_id:
            raise ValueError("a relationship must reference two distinct events")
        return self


class TemporalEventNode(StrictContract):
    event_id: UUID
    event_type: Literal["process", "file", "network", "configuration"]
    event_time: datetime
    observed_at: datetime
    received_at: datetime
    canonical_order: Annotated[int, Field(ge=0)]

    _event_utc = field_validator("event_time")(_utc)
    _observed_utc = field_validator("observed_at")(_utc)
    _received_utc = field_validator("received_at")(_utc)


class TemporalSequence(StrictContract):
    sequence_id: UUID
    relationship_type: RelationshipType
    event_ids: Annotated[
        tuple[UUID, ...], Field(min_length=2, max_length=MAX_EVENTS_PER_SEQUENCE)
    ]
    started_at: datetime
    ended_at: datetime
    confidence: RelationshipConfidence
    state: RelationshipState
    limitations: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=512)], ...],
        Field(max_length=8),
    ]

    _started_utc = field_validator("started_at")(_utc)
    _ended_utc = field_validator("ended_at")(_utc)

    @model_validator(mode="after")
    def validate_time_range(self) -> Self:
        if self.ended_at < self.started_at:
            raise ValueError("sequence end cannot precede its start")
        if len(set(self.event_ids)) != len(self.event_ids):
            raise ValueError("sequence event IDs must be unique")
        return self


class CorrelationIssue(StrictContract):
    code: Annotated[str, Field(pattern=r"^[A-Z][A-Z0-9_]{2,63}$")]
    severity: CorrelationIssueSeverity
    message: Annotated[str, Field(min_length=1, max_length=512)]
    event_ids: Annotated[tuple[UUID, ...], Field(max_length=16)]


class CorrelationSummary(StrictContract):
    submitted_event_count: int
    unique_event_count: int
    relationship_count: int
    sequence_count: int
    strong_relationships: int
    weak_relationships: int
    indeterminate_relationships: int
    issue_count: int
    input_was_out_of_order: bool
    equal_timestamp_groups: int
    relationships_truncated: bool
    sequences_truncated: bool


class TemporalCorrelationRequest(StrictContract):
    batch: EventBatch
    policy: CorrelationPolicy = Field(default_factory=CorrelationPolicy)


class TemporalCorrelationResult(StrictContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    batch_validation: EventValidationResult
    policy: CorrelationPolicy
    processing_time: datetime
    generated_at: datetime
    processing_time_policy: Literal["requested", "latest_received_at"]
    nodes: Annotated[tuple[TemporalEventNode, ...], Field(max_length=256)]
    relationships: Annotated[
        tuple[EventRelationship, ...], Field(max_length=MAX_CORRELATION_EDGES)
    ]
    sequences: Annotated[
        tuple[TemporalSequence, ...], Field(max_length=MAX_TEMPORAL_SEQUENCES)
    ]
    issues: Annotated[
        tuple[CorrelationIssue, ...], Field(max_length=MAX_CORRELATION_ISSUES)
    ]
    summary: CorrelationSummary
    limitations: tuple[Annotated[str, Field(min_length=1, max_length=512)], ...]
    causal_inference_performed: Literal[False] = False
    attack_mapping_performed: Literal[False] = False
    malware_classification_performed: Literal[False] = False
    persisted: Literal[False] = False

    _processing_utc = field_validator("processing_time")(_utc)
    _generated_utc = field_validator("generated_at")(_utc)


class TemporalCorrelationSchemaDescriptor(StrictContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    relationship_types: tuple[RelationshipType, ...]
    confidence_levels: tuple[RelationshipConfidence, ...]
    relationship_states: tuple[RelationshipState, ...]
    default_time_window_seconds: int
    maximum_time_window_seconds: int
    maximum_relationships: int
    maximum_relationships_per_event: int
    maximum_sequences: int
    maximum_events_per_sequence: int
    persistence: Literal[False] = False
    causal_inference: Literal[False] = False
    attack_mapping: Literal[False] = False
