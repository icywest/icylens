from __future__ import annotations

from typing import TypeAlias
from uuid import UUID

from app.schemas.behavior import EventUnion, FileEvent, NetworkEvent, ProcessEvent

ProcessKey: TypeAlias = tuple[str, UUID]
FileKey: TypeAlias = tuple[str, str]
ConnectionKey: TypeAlias = tuple[str, str, int, str, int, str, UUID]


def process_key(event: EventUnion) -> ProcessKey | None:
    process = event.process if hasattr(event, "process") else None
    if process is None:
        return None
    return event.host_id, process.process_instance_id


def declared_file_keys(event: FileEvent) -> tuple[FileKey, ...]:
    keys = [(event.host_id, event.file_path)]
    if event.destination_path is not None:
        keys.append((event.host_id, event.destination_path))
    return tuple(keys)


def declared_connection_key(event: NetworkEvent) -> ConnectionKey | None:
    if event.process is None:
        return None
    return (
        event.host_id,
        str(event.local_ip),
        event.local_port,
        str(event.remote_ip),
        event.remote_port,
        event.protocol.value,
        event.process.process_instance_id,
    )


def parent_key(event: ProcessEvent) -> ProcessKey | None:
    if event.parent_process is None:
        return None
    return event.host_id, event.parent_process.process_instance_id
