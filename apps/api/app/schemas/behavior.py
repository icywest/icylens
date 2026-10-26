from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Literal, TypeAlias
from uuid import UUID

from pydantic import (
    Field,
    IPvAnyAddress,
    field_serializer,
    field_validator,
    model_validator,
)

from app.schemas.vulnerability import StrictContract

BEHAVIOR_SCHEMA_VERSION = "1.0.0"
MAX_EVENTS_PER_BATCH = 256
MAX_SYNTHETIC_EVENTS = 100
MAX_EVENT_BYTES = 32 * 1024
MAX_BATCH_BYTES = 512 * 1024
MAX_GENERATION_BODY_BYTES = 64 * 1024
MAX_ATTRIBUTE_DEPTH = 4
MAX_ATTRIBUTE_ITEMS = 64
MAX_STRING_LENGTH = 4096


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return value.astimezone(timezone.utc)


def _validate_attribute(value: object, depth: int = 0) -> None:
    if depth > MAX_ATTRIBUTE_DEPTH:
        raise ValueError("attributes exceed the nesting limit")
    if value is None or isinstance(value, bool | int | float):
        return
    if isinstance(value, str):
        if len(value) > MAX_STRING_LENGTH:
            raise ValueError("attribute string exceeds the length limit")
        return
    if isinstance(value, dict):
        if len(value) > MAX_ATTRIBUTE_ITEMS:
            raise ValueError("attributes exceed the item limit")
        for key, child in value.items():
            if not isinstance(key, str) or not key or len(key) > 128:
                raise ValueError("attribute key is invalid")
            _validate_attribute(child, depth + 1)
        return
    if isinstance(value, list):
        if len(value) > MAX_ATTRIBUTE_ITEMS:
            raise ValueError("attribute list exceeds the item limit")
        for child in value:
            _validate_attribute(child, depth + 1)
        return
    raise ValueError("attributes contain an unsupported value")


class EventPlatform(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"


class EventSourceKind(str, Enum):
    SYNTHETIC_GENERATOR = "synthetic_generator"
    DECLARED_API = "declared_api"
    SENSOR_EXPORT = "sensor_export"


class EventNature(str, Enum):
    SYNTHETIC = "synthetic"
    DECLARED = "declared"


class EventSource(StrictContract):
    kind: EventSourceKind
    source_id: Annotated[str, Field(min_length=1, max_length=256)]
    producer: Annotated[str | None, Field(default=None, max_length=256)]


class EventProvenance(StrictContract):
    source_identifier: Annotated[str, Field(min_length=1, max_length=256)]
    observed_at: datetime
    received_at: datetime
    nature: EventNature
    missing_fields: tuple[Annotated[str, Field(min_length=1, max_length=128)], ...]
    limitations: tuple[Annotated[str, Field(min_length=1, max_length=512)], ...]

    _observed_utc = field_validator("observed_at")(_utc)
    _received_utc = field_validator("received_at")(_utc)

    @model_validator(mode="after")
    def validate_timeline(self) -> EventProvenance:
        if self.received_at < self.observed_at:
            raise ValueError("received_at must not precede observed_at")
        if len(set(self.missing_fields)) != len(self.missing_fields):
            raise ValueError("missing_fields must not contain duplicates")
        return self


class ProcessIdentity(StrictContract):
    process_instance_id: UUID
    pid: Annotated[int, Field(ge=1, le=4_294_967_295)]
    started_at: datetime

    _started_utc = field_validator("started_at")(_utc)


class BehavioralEvent(StrictContract):
    event_id: UUID
    event_type: str
    timestamp: datetime
    host_id: Annotated[str, Field(min_length=1, max_length=256)]
    source: EventSource
    platform: EventPlatform
    schema_version: Literal["1.0.0"] = "1.0.0"
    synthetic: bool
    provenance: EventProvenance
    attributes: dict[str, object] = Field(default_factory=dict)

    _timestamp_utc = field_validator("timestamp")(_utc)

    @field_validator("attributes")
    @classmethod
    def validate_attributes(cls, value: dict[str, object]) -> dict[str, object]:
        _validate_attribute(value)
        return value

    @model_validator(mode="after")
    def validate_common_semantics(self) -> BehavioralEvent:
        if self.source.source_id != self.provenance.source_identifier:
            raise ValueError("source and provenance identifiers must match")
        expected_synthetic = self.provenance.nature is EventNature.SYNTHETIC
        if self.synthetic != expected_synthetic:
            raise ValueError("synthetic flag and provenance nature must match")
        if self.provenance.observed_at < self.timestamp:
            raise ValueError("observed_at must not precede event time")
        encoded = json.dumps(
            self.model_dump(mode="json"), ensure_ascii=False, separators=(",", ":")
        ).encode()
        if len(encoded) > MAX_EVENT_BYTES:
            raise ValueError("event exceeds the serialized size limit")
        return self


class ProcessAction(str, Enum):
    START = "start"
    TERMINATE = "terminate"


class ProcessEvent(BehavioralEvent):
    event_type: Literal["process"]
    action: ProcessAction
    process: ProcessIdentity
    parent_process: ProcessIdentity | None = None
    executable_path: Annotated[str, Field(min_length=1, max_length=4096)]
    command_line: Annotated[str | None, Field(default=None, max_length=8192)]
    user_context: Annotated[str | None, Field(default=None, max_length=512)]
    exit_code: int | None = None

    @model_validator(mode="after")
    def validate_action_fields(self) -> ProcessEvent:
        if self.action is ProcessAction.START and self.exit_code is not None:
            raise ValueError("a process start cannot have an exit code")
        if self.process.started_at > self.timestamp:
            raise ValueError("process start time cannot follow the event")
        if self.parent_process == self.process:
            raise ValueError("a process cannot be its own parent")
        return self


class FileAction(str, Enum):
    CREATE = "create"
    MODIFY = "modify"
    DELETE = "delete"
    RENAME = "rename"


class FileHashes(StrictContract):
    sha256: Annotated[str | None, Field(default=None, pattern=r"^[0-9a-f]{64}$")]
    sha1: Annotated[str | None, Field(default=None, pattern=r"^[0-9a-f]{40}$")]

    @model_validator(mode="after")
    def require_hash(self) -> FileHashes:
        if self.sha256 is None and self.sha1 is None:
            raise ValueError("at least one declared hash is required")
        return self


class FileEvent(BehavioralEvent):
    event_type: Literal["file"]
    action: FileAction
    file_path: Annotated[str, Field(min_length=1, max_length=4096)]
    destination_path: Annotated[str | None, Field(default=None, max_length=4096)]
    hashes: FileHashes | None = None
    process: ProcessIdentity | None = None

    @model_validator(mode="after")
    def validate_rename(self) -> FileEvent:
        if (self.action is FileAction.RENAME) != (self.destination_path is not None):
            raise ValueError("destination_path is required only for rename events")
        return self


class NetworkAction(str, Enum):
    ATTEMPTED = "attempted"
    ESTABLISHED = "established"
    CLOSED = "closed"


class NetworkProtocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"


class NetworkEvent(BehavioralEvent):
    event_type: Literal["network"]
    action: NetworkAction
    local_ip: IPvAnyAddress
    local_port: Annotated[int, Field(ge=0, le=65535)]
    remote_ip: IPvAnyAddress
    remote_port: Annotated[int, Field(ge=1, le=65535)]
    protocol: NetworkProtocol
    process: ProcessIdentity | None = None

    @field_serializer("local_ip", "remote_ip")
    def serialize_ip(self, value: IPv4Address | IPv6Address) -> str:
        return str(value)


class ConfigurationKind(str, Enum):
    WINDOWS_REGISTRY = "windows_registry"
    SERVICE = "service"
    SCHEDULED_TASK = "scheduled_task"
    STARTUP = "startup"


class ConfigurationEvent(BehavioralEvent):
    event_type: Literal["configuration"]
    action: Literal["reported_change"]
    configuration_kind: ConfigurationKind
    target: Annotated[str, Field(min_length=1, max_length=4096)]
    previous_value: Annotated[str | None, Field(default=None, max_length=8192)]
    current_value: Annotated[str | None, Field(default=None, max_length=8192)]
    process: ProcessIdentity | None = None

    @model_validator(mode="after")
    def require_declared_value(self) -> ConfigurationEvent:
        if self.previous_value is None and self.current_value is None:
            raise ValueError("a configuration change requires a declared value")
        return self


EventUnion: TypeAlias = Annotated[
    ProcessEvent | FileEvent | NetworkEvent | ConfigurationEvent,
    Field(discriminator="event_type"),
]


class EventBatch(StrictContract):
    events: Annotated[
        tuple[EventUnion, ...], Field(min_length=1, max_length=MAX_EVENTS_PER_BATCH)
    ]


class ValidationSeverity(str, Enum):
    ERROR = "error"
    WARNING = "warning"


class EventValidationIssue(StrictContract):
    code: Annotated[str, Field(pattern=r"^[A-Z][A-Z0-9_]{2,63}$")]
    severity: ValidationSeverity
    message: Annotated[str, Field(min_length=1, max_length=512)]
    event_ids: tuple[UUID, ...]


class EventValidationResult(StrictContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    valid: bool
    event_count: int
    issues: tuple[EventValidationIssue, ...]
    limitations: tuple[Annotated[str, Field(min_length=1, max_length=512)], ...]


class SyntheticScenarioKind(str, Enum):
    NORMAL_PROCESS = "normal_process_lifecycle"
    FILE_SEQUENCE = "file_create_modify"
    NETWORK_SEQUENCE = "network_attempt_established"
    CONFIGURATION_CHANGE = "configuration_change"
    INCOMPLETE_SEQUENCE = "incomplete_sequence"
    OUT_OF_ORDER = "out_of_order"
    DUPLICATE_EVENTS = "duplicate_events"
    INCONSISTENT_PROCESS = "inconsistent_process_relationships"
    MISSING_OPTIONAL = "missing_optional_fields"
    CONTRADICTORY_DATA = "contradictory_data"


class SyntheticScenarioMetadata(StrictContract):
    scenario_id: Annotated[str, Field(min_length=1, max_length=128)]
    scenario_kind: SyntheticScenarioKind
    seed: Annotated[int, Field(ge=0, le=2_147_483_647)]
    platform: EventPlatform
    host_id: Annotated[str, Field(min_length=1, max_length=256)]
    start_time: datetime
    generated_at: datetime
    requested_event_count: Annotated[int, Field(ge=1, le=MAX_SYNTHETIC_EVENTS)]
    educational_only: Literal[True] = True

    _start_utc = field_validator("start_time")(_utc)
    _generated_utc = field_validator("generated_at")(_utc)


class SyntheticScenarioRequest(StrictContract):
    scenario_id: Annotated[str, Field(min_length=1, max_length=128)]
    scenario_kind: SyntheticScenarioKind
    seed: Annotated[int, Field(ge=0, le=2_147_483_647)]
    platform: EventPlatform
    start_time: datetime
    event_count: Annotated[int, Field(ge=1, le=MAX_SYNTHETIC_EVENTS)]

    _start_utc = field_validator("start_time")(_utc)

    @model_validator(mode="after")
    def validate_scenario_cardinality(self) -> SyntheticScenarioRequest:
        paired = {
            SyntheticScenarioKind.NORMAL_PROCESS,
            SyntheticScenarioKind.FILE_SEQUENCE,
            SyntheticScenarioKind.NETWORK_SEQUENCE,
        }
        if self.scenario_kind in paired and self.event_count % 2:
            raise ValueError("this scenario requires an even event count")
        if (
            self.scenario_kind
            in {
                SyntheticScenarioKind.OUT_OF_ORDER,
                SyntheticScenarioKind.DUPLICATE_EVENTS,
            }
            and self.event_count < 2
        ):
            raise ValueError("this scenario requires at least two events")
        return self


class SyntheticScenario(StrictContract):
    metadata: SyntheticScenarioMetadata
    events: tuple[EventUnion, ...]
    validation: EventValidationResult
    disclaimer: Literal[
        "Synthetic educational telemetry; not an endpoint observation or threat detection."
    ] = "Synthetic educational telemetry; not an endpoint observation or threat detection."


class BehavioralSchemaDescriptor(StrictContract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    event_types: tuple[Literal["process", "file", "network", "configuration"], ...]
    maximum_events_per_batch: int
    maximum_synthetic_events: int
    maximum_event_bytes: int
    maximum_batch_bytes: int
    maximum_attribute_depth: int
    persistence: Literal[False] = False
    attack_mapping: Literal[False] = False
    detection_semantics: Literal[False] = False
