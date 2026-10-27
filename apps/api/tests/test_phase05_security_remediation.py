from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
from copy import deepcopy
from datetime import timedelta
from pathlib import Path
from threading import Event

import pytest
from fastapi.testclient import TestClient

from app.attack.catalog import (
    ATTACK_ARTIFACT_SHA256,
    DEFAULT_SNAPSHOT_PATH,
    ATTACKCatalogStore,
    ATTACKCatalogValidationError,
    _load_fixture_snapshot,
    load_snapshot,
    load_verified_snapshot,
)
from app.behavior.rule_engine import BehavioralRuleEngine
from app.main import create_app
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
from app.schemas.behavior_rules import (
    REDACTED_EVIDENCE_VALUE,
    EvidenceField,
    RuleEvaluationRequest,
)
from app.services.synchronous_workers import SynchronousWorkerManager
from tests.test_behavioral_rules import NOW


def _official_payload() -> dict[str, object]:
    with gzip.open(DEFAULT_SNAPSHOT_PATH, "rb") as stream:
        payload = json.load(stream)
    assert isinstance(payload, dict)
    return payload


def _write_mutated_snapshot(path: Path, payload: object) -> None:
    path.write_bytes(
        gzip.compress(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(),
            mtime=0,
        )
    )


def _mutate_technique_name(payload: dict[str, object]) -> None:
    techniques = payload["techniques"]
    assert isinstance(techniques, list)
    techniques[0]["name"] = "TAMPERED TECHNIQUE"  # type: ignore[index]


def _mutate_technique_status(payload: dict[str, object]) -> None:
    techniques = payload["techniques"]
    assert isinstance(techniques, list)
    techniques[0]["revoked"] = not techniques[0].get("revoked", False)  # type: ignore[union-attr]


def _mutate_relationship(payload: dict[str, object]) -> None:
    relationships = payload["relationships"]
    assert isinstance(relationships, list)
    relationships[0]["relationship_type"] = "tampered"  # type: ignore[index]


def _mutate_tactic(payload: dict[str, object]) -> None:
    tactics = payload["tactics"]
    assert isinstance(tactics, list)
    tactics[0]["name"] = "TAMPERED TACTIC"  # type: ignore[index]


def _mutate_provenance(payload: dict[str, object]) -> None:
    provenance = payload["provenance"]
    assert isinstance(provenance, dict)
    provenance["attack_version"] = "19.1"


@pytest.mark.security
@pytest.mark.parametrize(
    "mutation",
    [
        _mutate_technique_name,
        _mutate_technique_status,
        _mutate_relationship,
        _mutate_tactic,
        _mutate_provenance,
    ],
)
def test_packaged_snapshot_rejects_semantically_valid_tampering(
    tmp_path: Path, mutation
) -> None:
    payload = deepcopy(_official_payload())
    mutation(payload)
    path = tmp_path / "tampered.json.gz"
    _write_mutated_snapshot(path, payload)

    with pytest.raises(ATTACKCatalogValidationError, match="artifact digest"):
        load_snapshot(path)


@pytest.mark.security
def test_packaged_snapshot_digest_is_external_and_checked_before_gzip(
    tmp_path: Path,
) -> None:
    artifact = DEFAULT_SNAPSHOT_PATH.read_bytes()
    assert hashlib.sha256(artifact).hexdigest() == ATTACK_ARTIFACT_SHA256
    snapshot = load_snapshot()
    assert snapshot.provenance.attack_version == "19.2"
    assert snapshot.statistics.technique_count == 858

    for name, candidate in (
        ("minimal-byte-change", artifact[:-1] + bytes([artifact[-1] ^ 1])),
        ("truncated", artifact[:100]),
        ("corrupt", b"not-a-gzip-stream"),
    ):
        path = tmp_path / f"{name}.gz"
        path.write_bytes(candidate)
        with pytest.raises(ATTACKCatalogValidationError, match="artifact digest"):
            load_snapshot(path)


@pytest.mark.security
def test_failed_tampered_replacement_does_not_replace_valid_snapshot(
    tmp_path: Path,
) -> None:
    verified = load_verified_snapshot()
    payload = deepcopy(_official_payload())
    _mutate_technique_name(payload)
    path = tmp_path / "tampered.json.gz"
    _write_mutated_snapshot(path, payload)
    store = ATTACKCatalogStore(path)
    store.publish(verified)

    with pytest.raises(ATTACKCatalogValidationError, match="artifact digest"):
        store.load()
    assert store.snapshot == verified.snapshot


@pytest.mark.security
def test_snapshot_read_and_decompression_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(ATTACKCatalogValidationError, match="cannot be read"):
        load_snapshot(tmp_path / "missing.gz")

    corrupt = tmp_path / "corrupt.gz"
    corrupt.write_bytes(b"not-a-gzip-stream")
    with pytest.raises(ATTACKCatalogValidationError, match="decompressed"):
        _load_fixture_snapshot(corrupt)


def _canary_events() -> tuple[
    ProcessEvent, FileEvent, NetworkEvent, ConfigurationEvent
]:
    source = EventSource(
        kind=EventSourceKind.DECLARED_API,
        source_id="SOURCE-CANARY-7f43",
        producer="PRODUCER-CANARY-7f43",
    )

    def base(offset: int) -> dict[str, object]:
        timestamp = NOW + timedelta(seconds=offset)
        return {
            "timestamp": timestamp,
            "host_id": "HOST-CANARY-7f43",
            "source": source,
            "platform": EventPlatform.WINDOWS,
            "synthetic": False,
            "provenance": EventProvenance(
                source_identifier=source.source_id,
                observed_at=timestamp,
                received_at=timestamp + timedelta(milliseconds=1),
                nature=EventNature.DECLARED,
                missing_fields=(),
                limitations=("CANARY-LIMITATION-7f43",),
            ),
            "attributes": {"secret": "ATTRIBUTE-CANARY-7f43"},
        }

    identity = ProcessIdentity(
        process_instance_id="11111111-1111-4111-8111-111111111111",
        pid=4242,
        started_at=NOW,
    )
    process = ProcessEvent(
        event_id="21111111-1111-4111-8111-111111111111",
        event_type="process",
        action=ProcessAction.START,
        process=identity,
        executable_path=r"C:\Users\alice\EXECUTABLE-CANARY-7f43.exe",
        command_line="COMMAND-CANARY-7f43 --secret TOKEN-CANARY-7f43",
        user_context="USERNAME-CANARY-7f43",
        **base(0),
    )
    file_event = FileEvent(
        event_id="31111111-1111-4111-8111-111111111111",
        event_type="file",
        action=FileAction.CREATE,
        file_path=r"C:\Users\alice\FILE-CANARY-7f43.txt",
        destination_path=None,
        hashes=None,
        process=None,
        **base(1),
    )
    network = NetworkEvent(
        event_id="41111111-1111-4111-8111-111111111111",
        event_type="network",
        action=NetworkAction.ATTEMPTED,
        local_ip="192.0.2.73",
        local_port=54743,
        remote_ip="198.51.100.73",
        remote_port=443,
        protocol=NetworkProtocol.TCP,
        process=None,
        **base(2),
    )
    configuration = ConfigurationEvent(
        event_id="51111111-1111-4111-8111-111111111111",
        event_type="configuration",
        action="reported_change",
        configuration_kind=ConfigurationKind.WINDOWS_REGISTRY,
        target=r"HKCU\REGISTRY-CANARY-7f43",
        previous_value="PREVIOUS-CANARY-7f43",
        current_value="CURRENT-CANARY-7f43",
        process=None,
        **base(3),
    )
    return process, file_event, network, configuration


@pytest.mark.security
def test_rule_evidence_and_http_response_remove_sensitive_canaries(
    client: TestClient,
) -> None:
    events = _canary_events()
    request = RuleEvaluationRequest(
        batch=EventBatch(events=events),
        rule_ids=("BR-PROC-003", "BR-FILE-003", "BR-NET-003", "BR-CONF-001"),
    )
    result = BehavioralRuleEngine().evaluate(request)
    serialized = result.model_dump_json()

    canaries = (
        "SOURCE-CANARY",
        "PRODUCER-CANARY",
        "HOST-CANARY",
        "EXECUTABLE-CANARY",
        "COMMAND-CANARY",
        "TOKEN-CANARY",
        "USERNAME-CANARY",
        "FILE-CANARY",
        "192.0.2.73",
        "54743",
        "198.51.100.73",
        "REGISTRY-CANARY",
        "PREVIOUS-CANARY",
        "CURRENT-CANARY",
        "ATTRIBUTE-CANARY",
    )
    assert REDACTED_EVIDENCE_VALUE in serialized
    assert all(canary not in serialized for canary in canaries)
    assert result.summary.matched == 4
    assert all(
        field.value == REDACTED_EVIDENCE_VALUE
        for finding in result.findings
        for evidence in finding.evidence
        for field in evidence.fields
        if field.redacted
    )

    response = client.post(
        "/api/v1/behavior/rules/evaluate",
        json=request.model_dump(mode="json"),
    )
    assert response.status_code == 200
    assert all(canary not in response.text for canary in canaries)


@pytest.mark.unit
def test_evidence_contract_enforces_real_redaction() -> None:
    with pytest.raises(ValueError, match="replace the original"):
        EvidenceField(field="file_path", value="private", redacted=True)
    with pytest.raises(ValueError, match="requires redacted=true"):
        EvidenceField(
            field="file_path",
            value=REDACTED_EVIDENCE_VALUE,
            redacted=False,
        )


@pytest.mark.anyio
async def test_worker_manager_rejects_invalid_unbalanced_and_closed_admission() -> None:
    with pytest.raises(ValueError, match="positive"):
        SynchronousWorkerManager(0)

    manager = SynchronousWorkerManager(1)
    assert await manager.try_acquire() is True
    assert await manager.try_acquire() is False
    await manager.release()
    with pytest.raises(RuntimeError, match="unbalanced"):
        await manager.release()
    await manager.aclose()
    assert await manager.try_acquire() is False


@pytest.mark.anyio
async def test_worker_submission_failure_restores_capacity() -> None:
    manager = SynchronousWorkerManager(1)
    manager._executor.shutdown(wait=True)  # noqa: SLF001 - controlled failure seam
    with pytest.raises(RuntimeError, match="cannot schedule"):
        manager.try_submit(lambda: None)
    assert manager.active == 0
    await manager.aclose()


@pytest.mark.anyio
async def test_worker_manager_owns_timeout_through_shutdown_and_is_idempotent() -> None:
    manager = SynchronousWorkerManager(1)
    started = Event()
    release = Event()
    finished = Event()

    def operation() -> str:
        started.set()
        release.wait()
        finished.set()
        return "complete"

    worker = manager.try_submit(operation)
    assert worker is not None
    while not started.is_set():
        await asyncio.sleep(0)
    with pytest.raises(TimeoutError):
        await manager.wait(worker, timeout=0.001)
    assert manager.active == 1
    assert manager.owned_workers == 1

    close_task = asyncio.create_task(manager.aclose())
    await asyncio.sleep(0)
    assert not close_task.done()
    assert manager.closed is True
    assert manager.try_submit(lambda: "late") is None
    release.set()
    await close_task
    await manager.aclose()
    assert finished.is_set()
    assert manager.active == 0
    assert manager.owned_workers == 0


@pytest.mark.anyio
async def test_worker_manager_has_no_queue_and_drains_four_real_workers() -> None:
    manager = SynchronousWorkerManager(4)
    started = tuple(Event() for _ in range(4))
    release = Event()

    def operation(index: int) -> int:
        started[index].set()
        release.wait()
        return index

    workers = tuple(
        manager.try_submit(lambda index=index: operation(index)) for index in range(4)
    )
    assert all(worker is not None for worker in workers)
    while not all(event.is_set() for event in started):
        await asyncio.sleep(0)
    assert manager.active == 4
    assert manager.try_submit(lambda: 5) is None

    close_task = asyncio.create_task(manager.aclose())
    await asyncio.sleep(0)
    assert not close_task.done()
    release.set()
    await close_task
    assert manager.active == 0
    assert manager.owned_workers == 0


@pytest.mark.anyio
async def test_worker_exception_is_observed_and_capacity_released() -> None:
    manager = SynchronousWorkerManager(1)

    def broken() -> None:
        raise RuntimeError("controlled worker failure")

    worker = manager.try_submit(broken)
    assert worker is not None
    with pytest.raises(RuntimeError, match="controlled worker failure"):
        await manager.wait(worker, timeout=1)
    await manager.aclose()
    assert manager.active == 0


@pytest.mark.integration
def test_fastapi_uses_one_shared_phase05_manager_and_drains_lifespan() -> None:
    application = create_app()
    manager = application.state.phase05_worker_manager
    assert application.state.attack_mapping_capacity is manager
    assert application.state.behavior_analysis_capacity is manager
    with TestClient(application) as client:
        assert client.get("/api/v1/attack/status").status_code == 200
        assert manager.closed is False
    assert manager.closed is True
    assert manager.active == 0
