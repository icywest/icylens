from __future__ import annotations

import asyncio
import gzip
import hashlib
import inspect
import json
from collections.abc import Callable
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from threading import Event

import pytest
from fastapi.testclient import TestClient

from app.attack.catalog import (
    ATTACK_ARTIFACT_SHA256,
    ATTACK_SOURCE_SHA256,
    DEFAULT_SNAPSHOT_PATH,
    ATTACKCatalogStore,
    ATTACKCatalogUnavailableError,
    ATTACKCatalogValidationError,
    VerifiedAttackCatalogSnapshot,
    _build_fixture_snapshot_from_stix,
    load_snapshot,
    load_verified_snapshot,
)
from app.main import create_app
from app.services.synchronous_workers import SynchronousWorkerManager

FIXTURE = Path(__file__).parent / "fixtures" / "attack_bundle_synthetic.json"
NOW = datetime(2026, 10, 26, tzinfo=timezone.utc)


def _official_payload() -> dict[str, object]:
    with gzip.open(DEFAULT_SNAPSHOT_PATH, "rb") as stream:
        payload = json.load(stream)
    assert isinstance(payload, dict)
    return payload


def _write_payload(path: Path, payload: object) -> None:
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
    provenance["imported_at"] = "2020-01-01T00:00:00Z"


def _fixture_snapshot():
    return _build_fixture_snapshot_from_stix(FIXTURE.read_bytes(), NOW)


@pytest.mark.security
def test_production_loader_has_no_digest_disable_parameter() -> None:
    parameters = inspect.signature(load_snapshot).parameters
    assert "expected_artifact_digest" not in parameters
    assert "expected_source_digest" not in parameters
    with pytest.raises(TypeError, match="unexpected keyword"):
        load_snapshot(expected_artifact_digest=None)  # type: ignore[call-arg]


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
def test_structurally_valid_mutations_fail_closed_before_publication(
    tmp_path: Path, mutation: Callable[[dict[str, object]], None]
) -> None:
    payload = deepcopy(_official_payload())
    mutation(payload)
    path = tmp_path / "mutated.json.gz"
    _write_payload(path, payload)

    with pytest.raises(ATTACKCatalogValidationError, match="artifact digest"):
        load_verified_snapshot(path)
    with pytest.raises(ATTACKCatalogValidationError, match="artifact digest"):
        load_snapshot(path)

    store = ATTACKCatalogStore(path)
    with pytest.raises(ATTACKCatalogValidationError, match="artifact digest"):
        store.load()
    with pytest.raises(ATTACKCatalogUnavailableError):
        _ = store.snapshot


@pytest.mark.security
@pytest.mark.parametrize(
    "case",
    ["corrupt", "empty", "truncated-100", "single-byte-change"],
)
def test_truncated_corrupt_and_single_byte_mutations_are_rejected(
    tmp_path: Path, case: str
) -> None:
    artifact = DEFAULT_SNAPSHOT_PATH.read_bytes()
    candidates = {
        "corrupt": b"not-a-gzip-stream",
        "empty": b"",
        "truncated-100": artifact[:100],
        "single-byte-change": artifact[:-1] + bytes([artifact[-1] ^ 1]),
    }
    path = tmp_path / "candidate.gz"
    path.write_bytes(candidates[case])
    if case == "single-byte-change":
        with pytest.raises(ATTACKCatalogValidationError, match="artifact digest"):
            load_verified_snapshot(path)
    else:
        with pytest.raises(ATTACKCatalogValidationError):
            load_verified_snapshot(path)


@pytest.mark.security
def test_unverified_fixture_and_published_object_cannot_enter_store() -> None:
    fixture = _fixture_snapshot()
    store = ATTACKCatalogStore()
    with pytest.raises(TypeError, match="VerifiedAttackCatalogSnapshot"):
        store.publish(fixture)  # type: ignore[arg-type]
    with pytest.raises(ATTACKCatalogUnavailableError):
        _ = store.snapshot

    class SubclassedVerified(VerifiedAttackCatalogSnapshot):
        pass

    verified = load_verified_snapshot()
    forged = SubclassedVerified(verified._artifact)  # noqa: SLF001
    with pytest.raises(TypeError, match="VerifiedAttackCatalogSnapshot"):
        store.publish(forged)


@pytest.mark.security
def test_verified_constructor_only_accepts_pinned_artifact_bytes(
    tmp_path: Path,
) -> None:
    artifact = DEFAULT_SNAPSHOT_PATH.read_bytes()
    verified = VerifiedAttackCatalogSnapshot(artifact)
    assert verified.artifact_sha256 == ATTACK_ARTIFACT_SHA256
    assert verified.artifact_size == len(artifact)
    assert verified.snapshot.provenance.source_digest == ATTACK_SOURCE_SHA256

    mutated = deepcopy(_official_payload())
    _mutate_technique_name(mutated)
    path = tmp_path / "mutated.json.gz"
    _write_payload(path, mutated)
    with pytest.raises(ATTACKCatalogValidationError, match="artifact digest"):
        VerifiedAttackCatalogSnapshot(path.read_bytes())

    verified.assert_artifact_pin()
    object.__setattr__(verified, "_artifact", b"tampered")
    with pytest.raises(ATTACKCatalogValidationError, match="artifact digest"):
        verified.assert_artifact_pin()


@pytest.mark.security
def test_verified_object_mutation_cannot_change_published_content() -> None:
    verified = load_verified_snapshot()
    official_name = verified.snapshot.techniques_by_id["T1059"].name
    assert official_name == "Command and Scripting Interpreter"

    with pytest.raises(AttributeError, match="immutable"):
        verified._snapshot = verified.snapshot  # noqa: SLF001

    techniques = dict(verified.snapshot.techniques_by_id)
    techniques["T1059"] = techniques["T1059"].model_copy(
        update={"name": "TAMPERED AFTER VERIFICATION"}
    )
    tampered = replace(verified.snapshot, techniques_by_id=techniques)
    object.__setattr__(verified, "_snapshot", tampered)
    assert verified.snapshot.techniques_by_id["T1059"].name == (
        "TAMPERED AFTER VERIFICATION"
    )

    store = ATTACKCatalogStore()
    store.publish(verified)
    assert store.snapshot.techniques_by_id["T1059"].name == official_name
    assert store.snapshot.techniques_by_id["T1059"].name != (
        "TAMPERED AFTER VERIFICATION"
    )


@pytest.mark.security
def test_publish_rebuilds_from_artifact_and_ignores_synthetic_snapshot() -> None:
    verified = load_verified_snapshot()
    fixture = _fixture_snapshot()
    object.__setattr__(verified, "_snapshot", fixture)

    store = ATTACKCatalogStore()
    store.publish(verified)
    assert store.snapshot.statistics.technique_count == 858
    assert store.snapshot.statistics.relationship_count == 21262
    assert store.snapshot.techniques_by_id["T1059"].name == (
        "Command and Scripting Interpreter"
    )


@pytest.mark.security
def test_failed_republish_does_not_replace_valid_catalog() -> None:
    store = ATTACKCatalogStore()
    store.load()
    previous = store.snapshot
    verified = load_verified_snapshot()
    object.__setattr__(verified, "_artifact", b"tampered")

    with pytest.raises(ATTACKCatalogValidationError, match="artifact digest"):
        store.publish(verified)
    assert store.snapshot is previous


@pytest.mark.security
def test_failed_load_and_mutation_never_replace_valid_catalog(tmp_path: Path) -> None:
    store = ATTACKCatalogStore()
    store.load()
    original = store.snapshot
    assert original.statistics.technique_count == 858

    mutated = deepcopy(_official_payload())
    _mutate_technique_name(mutated)
    path = tmp_path / "mutated.json.gz"
    _write_payload(path, mutated)
    replacing = ATTACKCatalogStore(path)
    replacing.publish(load_verified_snapshot())
    previous = replacing.snapshot
    with pytest.raises(ATTACKCatalogValidationError, match="artifact digest"):
        replacing.load()
    assert replacing.snapshot is previous
    assert previous is not original


@pytest.mark.security
def test_repeated_verified_loads_are_stable() -> None:
    first = load_verified_snapshot()
    second = load_verified_snapshot()
    assert first.artifact_sha256 == second.artifact_sha256
    assert first.snapshot.statistics == second.snapshot.statistics
    assert first.snapshot.provenance == second.snapshot.provenance
    assert first.snapshot.techniques_by_id["T1059"].name == (
        "Command and Scripting Interpreter"
    )


@pytest.mark.integration
def test_packaged_attack_resource_is_the_verified_artifact() -> None:
    artifact = DEFAULT_SNAPSHOT_PATH.read_bytes()
    assert hashlib.sha256(artifact).hexdigest() == ATTACK_ARTIFACT_SHA256
    verified = load_verified_snapshot()
    assert verified.artifact_size == len(artifact)
    assert verified.snapshot.statistics.technique_count == 858
    assert verified.snapshot.statistics.relationship_count == 21262


@pytest.mark.integration
def test_application_composition_uses_verified_store_load() -> None:
    application = create_app()
    with TestClient(application):
        attack_store = application.state.attack_store
        assert isinstance(attack_store, ATTACKCatalogStore)
        assert attack_store.snapshot.provenance.source_digest == ATTACK_SOURCE_SHA256


def _started(event: Event) -> None:
    event.set()


async def _wait_for(events: tuple[Event, ...]) -> None:
    while not all(event.is_set() for event in events):
        await asyncio.sleep(0)


def _executor_shutdown(manager: SynchronousWorkerManager) -> bool:
    return manager._executor._shutdown  # noqa: SLF001


def _close_task(manager: SynchronousWorkerManager) -> asyncio.Task[None]:
    task = manager._close_task  # noqa: SLF001
    assert task is not None
    return task


@pytest.mark.anyio
async def test_close_without_workers_completes_immediately() -> None:
    manager = SynchronousWorkerManager(2)
    await manager.aclose()
    assert manager.shutdown_complete is True
    assert manager.active == 0
    assert manager.owned_workers == 0
    assert _executor_shutdown(manager) is True
    await manager.aclose()


@pytest.mark.anyio
async def test_cancelled_first_waiter_does_not_cancel_shared_close() -> None:
    manager = SynchronousWorkerManager(1)
    started = Event()
    release = Event()

    def operation() -> str:
        _started(started)
        release.wait()
        return "complete"

    worker = manager.try_submit(operation)
    assert worker is not None
    await _wait_for((started,))

    first = asyncio.create_task(manager.aclose())
    second = asyncio.create_task(manager.aclose())
    await asyncio.sleep(0)
    assert manager.closed is True
    assert manager.try_submit(lambda: "late") is None

    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first
    await asyncio.sleep(0)
    assert manager.shutdown_complete is False
    assert manager.active == 1
    assert manager.owned_workers == 1
    assert _executor_shutdown(manager) is False

    release.set()
    await second
    assert manager.shutdown_complete is True
    assert manager.active == 0
    assert manager.owned_workers == 0
    assert _executor_shutdown(manager) is True
    assert _close_task(manager).done()


@pytest.mark.anyio
async def test_cancelled_second_and_remaining_waiters_keep_close_alive() -> None:
    manager = SynchronousWorkerManager(1)
    started = Event()
    release = Event()

    def operation() -> None:
        _started(started)
        release.wait()

    worker = manager.try_submit(operation)
    assert worker is not None
    await _wait_for((started,))

    first = asyncio.create_task(manager.aclose())
    second = asyncio.create_task(manager.aclose())
    third = asyncio.create_task(manager.aclose())
    await asyncio.sleep(0)
    second.cancel()
    third.cancel()
    with pytest.raises(asyncio.CancelledError):
        await second
    with pytest.raises(asyncio.CancelledError):
        await third
    release.set()
    await first
    assert manager.shutdown_complete is True
    assert manager.active == 0
    assert manager.owned_workers == 0
    assert _executor_shutdown(manager) is True


@pytest.mark.anyio
async def test_cancelling_every_waiter_still_finishes_without_second_call() -> None:
    manager = SynchronousWorkerManager(1)
    started = Event()
    release = Event()

    def operation() -> None:
        _started(started)
        release.wait()

    worker = manager.try_submit(operation)
    assert worker is not None
    await _wait_for((started,))

    waiter = asyncio.create_task(manager.aclose())
    await asyncio.sleep(0)
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    release.set()
    await asyncio.shield(_close_task(manager))
    assert manager.shutdown_complete is True
    assert manager.active == 0
    assert manager.owned_workers == 0
    assert _executor_shutdown(manager) is True


@pytest.mark.anyio
async def test_immediate_waiter_cancellation_is_safe() -> None:
    manager = SynchronousWorkerManager(1)
    started = Event()
    release = Event()

    def operation() -> None:
        _started(started)
        release.wait()

    worker = manager.try_submit(operation)
    assert worker is not None
    await _wait_for((started,))

    waiter = asyncio.create_task(manager.aclose())
    await asyncio.sleep(0)
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    assert manager.closed is True
    release.set()
    await asyncio.shield(_close_task(manager))
    assert manager.shutdown_complete is True
    assert manager.active == 0
    assert _executor_shutdown(manager) is True


@pytest.mark.anyio
async def test_waiter_cancelled_before_first_step_never_started_close() -> None:
    manager = SynchronousWorkerManager(1)
    started = Event()
    release = Event()

    def operation() -> None:
        _started(started)
        release.wait()

    worker = manager.try_submit(operation)
    assert worker is not None
    await _wait_for((started,))

    waiter = asyncio.create_task(manager.aclose())
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    assert manager.closed is False
    assert manager.shutdown_complete is False
    release.set()
    await manager.aclose()
    assert manager.shutdown_complete is True
    assert manager.active == 0
    assert _executor_shutdown(manager) is True


@pytest.mark.anyio
async def test_late_worker_failure_after_cancelled_close_is_consumed() -> None:
    manager = SynchronousWorkerManager(1)
    started = Event()
    release = Event()

    def operation() -> None:
        _started(started)
        release.wait()
        raise RuntimeError("late controlled failure")

    worker = manager.try_submit(operation)
    assert worker is not None
    await _wait_for((started,))

    waiter = asyncio.create_task(manager.aclose())
    await asyncio.sleep(0)
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    release.set()
    await asyncio.shield(_close_task(manager))
    assert worker.exception() is not None
    assert manager.shutdown_complete is True
    assert manager.active == 0
    assert manager.owned_workers == 0
    assert _executor_shutdown(manager) is True


@pytest.mark.anyio
async def test_resistant_worker_blocks_completion_until_release() -> None:
    manager = SynchronousWorkerManager(1)
    started = Event()
    release = Event()

    def operation() -> None:
        _started(started)
        release.wait()

    worker = manager.try_submit(operation)
    assert worker is not None
    await _wait_for((started,))
    close = asyncio.create_task(manager.aclose())
    await asyncio.sleep(0)
    for _ in range(5):
        await asyncio.sleep(0)
        assert close.done() is False
        assert manager.shutdown_complete is False
        assert manager.active == 1
    release.set()
    await close
    assert manager.shutdown_complete is True
    assert manager.active == 0
    assert manager.owned_workers == 0


@pytest.mark.anyio
async def test_four_workers_drain_and_fifth_is_rejected_after_close() -> None:
    manager = SynchronousWorkerManager(4)
    started = tuple(Event() for _ in range(4))
    release = Event()

    def operation(index: int) -> None:
        _started(started[index])
        release.wait()

    workers = tuple(
        manager.try_submit(lambda index=index: operation(index)) for index in range(4)
    )
    assert all(worker is not None for worker in workers)
    await _wait_for(started)
    assert manager.active == 4
    assert manager.try_submit(lambda: None) is None

    close = asyncio.create_task(manager.aclose())
    await asyncio.sleep(0)
    assert manager.try_submit(lambda: None) is None
    release.set()
    await close
    assert manager.shutdown_complete is True
    assert manager.active == 0
    assert manager.owned_workers == 0
    assert _executor_shutdown(manager) is True


@pytest.mark.integration
def test_mapping_and_unified_share_cancellation_safe_manager() -> None:
    application = create_app()
    manager = application.state.phase05_worker_manager
    assert application.state.attack_mapping_capacity is manager
    assert application.state.behavior_analysis_capacity is manager
    assert manager.maximum == 4
