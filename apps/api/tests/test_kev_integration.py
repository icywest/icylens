from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

import app.intelligence.kev_catalog as kev_catalog_module
from app.core.config import Settings
from app.integrations.cisa_kev.client import (
    FetchedKEVCatalog,
    KEVClient,
    KEVInvalidResponseError,
    KEVRateLimitError,
    KEVResponseTooLargeError,
    KEVTimeoutError,
    KEVUnavailableError,
    validate_kev_endpoint,
)
from app.integrations.cisa_kev.schemas import CISAKEVCatalog
from app.intelligence.kev_catalog import (
    KEVCatalogSnapshot,
    KEVCatalogStore,
    KEVCatalogUnavailableError,
    KEVCatalogValidationError,
    build_snapshot,
)
from app.main import create_app
from app.schemas.kev import KEVFreshnessStatus, KEVPresenceStatus

NOW = datetime(2026, 10, 25, 18, 0, tzinfo=timezone.utc)
ENDPOINT = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


def entry(cve_id: str = "CVE-2099-9999", **updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "cveID": cve_id,
        "vendorProject": "Synthetic Test Vendor",
        "product": "Synthetic Test Product",
        "vulnerabilityName": "Synthetic Test Vulnerability",
        "dateAdded": "2026-10-20",
        "shortDescription": "Offline deterministic test fixture; not live intelligence.",
        "requiredAction": "Apply the synthetic fixture mitigation.",
        "dueDate": "2026-11-10",
        "knownRansomwareCampaignUse": "Unknown",
        "forensicTriage": "No",
        "notes": "Synthetic fixture only.",
        "cwes": ["CWE-79"],
    }
    value.update(updates)
    return value


def payload(entries: list[dict[str, object]] | None = None) -> dict[str, object]:
    values = [entry()] if entries is None else entries
    return {
        "title": "Synthetic CISA KEV test catalog",
        "catalogVersion": "2099.10.20",
        "dateReleased": "2026-10-24T12:00:00Z",
        "count": len(values),
        "vulnerabilities": values,
    }


def settings(**updates: object) -> Settings:
    values: dict[str, object] = {
        "APP_ENV": "testing",
        "KEV_MAX_RETRIES": 0,
        "KEV_MAX_ENTRIES": 10,
        "_env_file": None,
    }
    values.update(updates)
    return Settings(**values)  # type: ignore[arg-type]


def encoded(value: dict[str, object]) -> bytes:
    return json.dumps(value).encode()


def fetched(
    value: dict[str, object] | None = None, digest: str | None = None
) -> FetchedKEVCatalog:
    body = encoded(value or payload())
    return FetchedKEVCatalog(
        catalog=CISAKEVCatalog.model_validate_json(body),
        content_digest=digest or hashlib.sha256(body).hexdigest(),
        decoded_bytes=len(body),
    )


class StubFetcher:
    def __init__(self, *results: FetchedKEVCatalog | Exception) -> None:
        self.results = list(results)
        self.calls = 0

    async def fetch_catalog(self) -> FetchedKEVCatalog:
        self.calls += 1
        await asyncio.sleep(0)
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


class LifecycleKEVClient(StubFetcher):
    def __init__(self, *results: FetchedKEVCatalog | Exception) -> None:
        super().__init__(*results)
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True


class BlockingKEVFetcher:
    def __init__(
        self,
        result: FetchedKEVCatalog | Exception,
        *,
        suppress_cancellation: bool = False,
    ) -> None:
        self.result = result
        self.suppress_cancellation = suppress_cancellation
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.cancelled = asyncio.Event()
        self.finish_after_cancellation = asyncio.Event()
        self.calls = 0

    async def fetch_catalog(self) -> FetchedKEVCatalog:
        self.calls += 1
        self.started.set()
        try:
            await self.release.wait()
        except asyncio.CancelledError:
            self.cancelled.set()
            if not self.suppress_cancellation:
                raise
            await self.finish_after_cancellation.wait()
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class PromotionObservedKEVStore(KEVCatalogStore):
    def __init__(self, configured: Settings) -> None:
        super().__init__(configured, now=lambda: NOW)
        self.promotion_started = asyncio.Event()

    async def _promote_if_authorized(self, candidate: KEVCatalogSnapshot) -> bool:
        self.promotion_started.set()
        return await super()._promote_if_authorized(candidate)


class InstrumentedStream(httpx.AsyncByteStream):
    def __init__(
        self,
        chunks: list[bytes],
        *,
        fail_before_chunk: int | None = None,
        wait: asyncio.Event | None = None,
    ) -> None:
        self.chunks = chunks
        self.fail_before_chunk = fail_before_chunk
        self.wait = wait
        self.chunks_requested = 0
        self.completed = False
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        if self.wait is not None:
            await self.wait.wait()
        for index, chunk in enumerate(self.chunks):
            if self.fail_before_chunk == index:
                raise httpx.ReadError("synthetic interrupted stream")
            self.chunks_requested += 1
            yield chunk
        self.completed = True

    async def aclose(self) -> None:
        self.closed = True


def make_client(handler: Any, **updates: object) -> KEVClient:
    return KEVClient(settings(**updates), transport=httpx.MockTransport(handler))


@pytest.mark.unit
@pytest.mark.parametrize(
    "value",
    [
        "http://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "https://cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        ENDPOINT + "?source=user",
        "https://user:secret@www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    ],
)
def test_endpoint_allowlist_rejects_noncanonical_values(value: str) -> None:
    with pytest.raises(ValueError, match="approved HTTPS"):
        validate_kev_endpoint(value)
    assert validate_kev_endpoint(ENDPOINT) == ENDPOINT


@pytest.mark.contract
def test_provider_contract_accepts_current_optional_fields_and_unknown_extensions() -> (
    None
):
    value = payload()
    value["futureEnvelopeField"] = {"ignored": True}
    item = value["vulnerabilities"][0]  # type: ignore[index]
    item["futureRecordField"] = "preserved only at provider boundary"
    catalog = CISAKEVCatalog.model_validate(value)
    assert catalog.vulnerabilities[0].forensicTriage == "No"
    assert catalog.vulnerabilities[0].cwes == ("CWE-79",)


@pytest.mark.contract
@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.pop("catalogVersion"), "validation"),
        (lambda value: value.update(dateReleased="not-a-date"), "validation"),
        (lambda value: value.update(vulnerabilities="partial"), "validation"),
        (lambda value: value["vulnerabilities"][0].pop("requiredAction"), "validation"),
        (lambda value: value["vulnerabilities"][0].update(cveID="bad"), "validation"),
        (
            lambda value: value["vulnerabilities"][0].update(cwes=["not-cwe"]),
            "validation",
        ),
    ],
)
def test_provider_contract_rejects_missing_or_invalid_required_data(
    mutation: Any, message: str
) -> None:
    value = payload()
    mutation(value)
    with pytest.raises(ValidationError, match=message):
        CISAKEVCatalog.model_validate(value)


@pytest.mark.unit
def test_valid_empty_catalog_builds_immutable_snapshot() -> None:
    snapshot = build_snapshot(fetched(payload([])), NOW, 10)
    assert snapshot.record_count == 0
    assert snapshot.validation_status == "validated"
    with pytest.raises(TypeError):
        snapshot.records_by_cve["CVE-2099-9999"] = object()  # type: ignore[index]


@pytest.mark.unit
@pytest.mark.parametrize(
    "value",
    [
        {**payload(), "count": 2},
        payload([entry(), entry()]),
        payload([entry(dueDate="2026-01-01")]),
        {**payload(), "dateReleased": "2026-10-26T12:00:00Z"},
    ],
)
def test_snapshot_rejects_count_duplicates_and_contradictions(
    value: dict[str, object],
) -> None:
    with pytest.raises(KEVCatalogValidationError):
        build_snapshot(fetched(value), NOW, 10)


@pytest.mark.unit
def test_snapshot_rejects_too_many_records_and_naive_times() -> None:
    with pytest.raises(KEVCatalogValidationError, match="entry limit"):
        build_snapshot(fetched(payload([entry(), entry("CVE-2099-9998")])), NOW, 1)
    with pytest.raises(KEVCatalogValidationError, match="retrieval time"):
        build_snapshot(fetched(), NOW.replace(tzinfo=None), 10)


@pytest.mark.unit
def test_unknown_ransomware_value_and_missing_optionals_are_preserved() -> None:
    value = entry(knownRansomwareCampaignUse="FutureValue")
    value.pop("notes")
    value.pop("cwes")
    value.pop("forensicTriage")
    snapshot = build_snapshot(fetched(payload([value])), NOW, 10)
    record = snapshot.records_by_cve["CVE-2099-9999"]
    assert record.known_ransomware_campaign_use == "FutureValue"
    assert record.notes is None
    assert record.cwes is None
    assert record.forensic_triage is None


@pytest.mark.unit
@pytest.mark.parametrize("published", ["Known", "Unknown", "FutureValue"])
def test_ransomware_value_is_source_text_not_an_inferred_boolean(
    published: str,
) -> None:
    snapshot = build_snapshot(
        fetched(payload([entry(knownRansomwareCampaignUse=published)])), NOW, 10
    )
    record = snapshot.records_by_cve["CVE-2099-9999"]
    assert record.known_ransomware_campaign_use == published
    assert "ransomware_confirmed" not in record.model_dump()


@pytest.mark.unit
def test_store_fresh_stale_and_absence_semantics() -> None:
    current = [NOW]
    store = KEVCatalogStore(settings(), now=lambda: current[0])
    asyncio.run(store.refresh(StubFetcher(fetched())))
    listed = store.lookup("CVE-2099-9999")
    absent = store.lookup("CVE-2099-9998")
    assert listed.presence is KEVPresenceStatus.LISTED
    assert absent.presence is KEVPresenceStatus.NOT_LISTED
    assert absent.catalog.availability is KEVFreshnessStatus.FRESH

    current[0] += timedelta(seconds=settings().KEV_FRESHNESS_SECONDS + 1)
    stale_absent = store.lookup("CVE-2099-9998")
    assert stale_absent.presence is KEVPresenceStatus.NOT_ESTABLISHED
    assert stale_absent.catalog.availability is KEVFreshnessStatus.STALE
    assert "stale" in stale_absent.limitations[-1]


@pytest.mark.unit
def test_never_loaded_and_failed_refresh_are_distinct() -> None:
    store = KEVCatalogStore(settings(), now=lambda: NOW)
    assert store.status().availability is KEVFreshnessStatus.NEVER_LOADED
    with pytest.raises(KEVCatalogUnavailableError):
        store.lookup("CVE-2099-9999")
    with pytest.raises(KEVUnavailableError):
        asyncio.run(store.refresh(StubFetcher(KEVUnavailableError("offline"))))
    assert store.status().availability is KEVFreshnessStatus.UNAVAILABLE


@pytest.mark.unit
def test_failed_or_conflicting_refresh_preserves_last_valid_snapshot() -> None:
    store = KEVCatalogStore(settings(), now=lambda: NOW)
    original = asyncio.run(store.refresh(StubFetcher(fetched(digest="a" * 64))))
    with pytest.raises(KEVUnavailableError):
        asyncio.run(store.refresh(StubFetcher(KEVUnavailableError("offline"))))
    assert store.snapshot is original
    with pytest.raises(KEVCatalogValidationError, match="conflicts"):
        asyncio.run(store.refresh(StubFetcher(fetched(digest="b" * 64))))
    assert store.snapshot is original


@pytest.mark.unit
def test_older_catalog_cannot_replace_active_snapshot() -> None:
    store = KEVCatalogStore(settings(), now=lambda: NOW)
    original = asyncio.run(store.refresh(StubFetcher(fetched())))
    older = payload()
    older["catalogVersion"] = "2099.10.19"
    older["dateReleased"] = "2026-10-23T12:00:00Z"
    with pytest.raises(KEVCatalogValidationError, match="predates"):
        asyncio.run(store.refresh(StubFetcher(fetched(older))))
    assert store.snapshot is original


@pytest.mark.unit
def test_concurrent_refreshes_are_coalesced_and_lookups_do_not_fetch() -> None:
    fetcher = StubFetcher(fetched())
    store = KEVCatalogStore(settings(), now=lambda: NOW)

    async def run() -> None:
        first, second = await asyncio.gather(
            store.refresh(fetcher), store.refresh(fetcher)
        )
        assert first is second

    asyncio.run(run())
    assert fetcher.calls == 1
    assert store.lookup("CVE-2099-9999") == store.lookup("CVE-2099-9999")
    assert fetcher.calls == 1


@pytest.mark.security
def test_refresh_releases_lock_coalesces_and_survives_consumer_cancel() -> None:
    async def exercise() -> None:
        fetcher = BlockingKEVFetcher(fetched())
        store = KEVCatalogStore(settings(), now=lambda: NOW)
        first = asyncio.create_task(store.refresh(fetcher))
        await fetcher.started.wait()
        second = asyncio.create_task(store.refresh(fetcher))
        await asyncio.sleep(0)

        async with asyncio.timeout(0.1):
            async with store._refresh_lock:
                registered = store._refresh_task
                assert registered is not None
        assert fetcher.calls == 1

        first.cancel()
        first_result = await asyncio.gather(first, return_exceptions=True)
        assert isinstance(first_result[0], asyncio.CancelledError)
        assert not fetcher.cancelled.is_set()
        assert not second.done()

        fetcher.release.set()
        result = await second
        assert result is store.snapshot
        assert fetcher.calls == 1
        assert store._refresh_task is None
        assert [
            task
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and not task.done()
        ] == []
        await store.aclose()

    asyncio.run(exercise())


@pytest.mark.security
def test_service_owned_refresh_outlives_its_only_cancelled_consumer() -> None:
    async def exercise() -> None:
        fetcher = BlockingKEVFetcher(fetched())
        store = KEVCatalogStore(settings(), now=lambda: NOW)
        consumer = asyncio.create_task(store.refresh(fetcher))
        await fetcher.started.wait()
        operation = store._refresh_task
        assert operation is not None

        consumer.cancel()
        outcome = await asyncio.gather(consumer, return_exceptions=True)
        assert isinstance(outcome[0], asyncio.CancelledError)
        assert not operation.done()
        assert not fetcher.cancelled.is_set()

        fetcher.release.set()
        result = await operation
        assert store.snapshot is result
        assert store._refresh_task is None
        await store.aclose()

    asyncio.run(exercise())


@pytest.mark.security
def test_coalesced_provider_failure_preserves_snapshot_and_cleans_task() -> None:
    async def exercise() -> None:
        store = KEVCatalogStore(settings(), now=lambda: NOW)
        original = await store.refresh(StubFetcher(fetched()))
        fetcher = BlockingKEVFetcher(KEVUnavailableError("offline"))
        first = asyncio.create_task(store.refresh(fetcher))
        second = asyncio.create_task(store.refresh(fetcher))
        await fetcher.started.wait()
        await asyncio.sleep(0)
        fetcher.release.set()

        outcomes = await asyncio.gather(first, second, return_exceptions=True)
        assert all(isinstance(item, KEVUnavailableError) for item in outcomes)
        assert fetcher.calls == 1
        assert store.snapshot is original
        assert store._refresh_task is None
        assert [
            task
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and not task.done()
        ] == []
        await store.aclose()

    asyncio.run(exercise())


@pytest.mark.security
def test_coalesced_invalid_candidate_never_replaces_active_snapshot() -> None:
    async def exercise() -> None:
        store = KEVCatalogStore(settings(), now=lambda: NOW)
        original = await store.refresh(StubFetcher(fetched()))
        invalid = payload()
        invalid["count"] = 2
        fetcher = BlockingKEVFetcher(fetched(invalid))
        first = asyncio.create_task(store.refresh(fetcher))
        second = asyncio.create_task(store.refresh(fetcher))
        await fetcher.started.wait()
        await asyncio.sleep(0)
        fetcher.release.set()

        outcomes = await asyncio.gather(first, second, return_exceptions=True)
        assert all(isinstance(item, KEVCatalogValidationError) for item in outcomes)
        assert fetcher.calls == 1
        assert store.snapshot is original
        assert store._refresh_task is None
        await store.aclose()

    asyncio.run(exercise())


@pytest.mark.security
def test_cancellation_during_validation_cannot_publish(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_builder = kev_catalog_module.build_snapshot

    def cancel_after_validation(
        candidate: FetchedKEVCatalog,
        fetched_at: datetime,
        maximum_entries: int,
    ) -> KEVCatalogSnapshot:
        snapshot = original_builder(candidate, fetched_at, maximum_entries)
        task = asyncio.current_task()
        assert task is not None
        task.cancel()
        return snapshot

    monkeypatch.setattr(kev_catalog_module, "build_snapshot", cancel_after_validation)

    async def exercise() -> None:
        store = KEVCatalogStore(settings(), now=lambda: NOW)
        outcome = await asyncio.gather(
            store.refresh(StubFetcher(fetched())), return_exceptions=True
        )
        assert isinstance(outcome[0], asyncio.CancelledError)
        assert store.snapshot is None
        assert store._refresh_task is None
        await store.aclose()

    asyncio.run(exercise())


@pytest.mark.security
def test_shutdown_fences_cancellation_suppression_and_collects() -> None:
    async def exercise() -> None:
        store = KEVCatalogStore(settings(), now=lambda: NOW)
        original = await store.refresh(StubFetcher(fetched(digest="a" * 64)))
        newer = payload([entry("CVE-2099-9998")])
        newer["catalogVersion"] = "2099.10.21"
        newer["dateReleased"] = "2026-10-25T12:00:00Z"
        fetcher = BlockingKEVFetcher(fetched(newer), suppress_cancellation=True)
        waiter = asyncio.create_task(store.refresh(fetcher))
        await fetcher.started.wait()

        shutdown = asyncio.create_task(store.aclose())
        await fetcher.cancelled.wait()
        assert store._closed is True
        assert store._refresh_task is None
        assert store.snapshot is original

        fetcher.finish_after_cancellation.set()
        await shutdown
        outcome = await asyncio.gather(waiter, return_exceptions=True)
        assert isinstance(outcome[0], asyncio.CancelledError)
        assert store.snapshot is original
        with pytest.raises(RuntimeError, match="closed"):
            await store.refresh(fetcher)
        assert [
            task
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and not task.done()
        ] == []

    asyncio.run(exercise())


@pytest.mark.security
def test_shutdown_wins_before_atomic_snapshot_promotion() -> None:
    async def exercise() -> None:
        store = PromotionObservedKEVStore(settings())
        fetcher = BlockingKEVFetcher(fetched())
        waiter = asyncio.create_task(store.refresh(fetcher))
        await fetcher.started.wait()

        await store._refresh_lock.acquire()
        try:
            shutdown = asyncio.create_task(store.aclose())
            await asyncio.sleep(0)
            fetcher.release.set()
            await store.promotion_started.wait()
        finally:
            store._refresh_lock.release()

        await shutdown
        outcome = await asyncio.gather(waiter, return_exceptions=True)
        assert isinstance(outcome[0], asyncio.CancelledError)
        assert store.snapshot is None
        assert store._refresh_task is None
        assert [
            task
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and not task.done()
        ] == []

    asyncio.run(exercise())


@pytest.mark.security
def test_lookup_remains_available_during_background_refresh() -> None:
    async def exercise() -> None:
        store = KEVCatalogStore(settings(), now=lambda: NOW)
        original = await store.refresh(StubFetcher(fetched()))
        update = payload([entry("CVE-2099-9998")])
        update["catalogVersion"] = "2099.10.21"
        update["dateReleased"] = "2026-10-25T12:00:00Z"
        fetcher = BlockingKEVFetcher(fetched(update))
        refresh = asyncio.create_task(store.refresh(fetcher))
        await fetcher.started.wait()

        assert store.lookup("CVE-2099-9999").record is not None
        assert store.snapshot is original
        assert not refresh.done()
        assert fetcher.calls == 1

        fetcher.release.set()
        promoted = await refresh
        assert promoted is store.snapshot
        assert store.lookup("CVE-2099-9998").record is not None
        assert fetcher.calls == 1
        assert store._refresh_task is None
        await store.aclose()

    asyncio.run(exercise())


@pytest.mark.integration
def test_client_streams_valid_catalog_and_uses_hardened_http_policy() -> None:
    requests: list[httpx.Request] = []
    stream = InstrumentedStream([encoded(payload())])

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            stream=stream,
        )

    client = make_client(handler)
    result = asyncio.run(client.fetch_catalog())
    asyncio.run(client.aclose())
    assert result.catalog.count == 1
    assert result.decoded_bytes == len(encoded(payload()))
    assert requests[0].url == ENDPOINT
    assert stream.completed and stream.closed
    assert client._http._trust_env is False


@pytest.mark.security
def test_client_aborts_oversized_plain_stream_before_consuming_all_chunks() -> None:
    stream = InstrumentedStream([b"x" * 600_000, b"y" * 600_000, b"z" * 10])
    client = make_client(
        lambda _: httpx.Response(
            200, headers={"content-type": "application/json"}, stream=stream
        ),
        KEV_MAX_RESPONSE_BYTES=1024 * 1024,
    )
    with pytest.raises(KEVResponseTooLargeError):
        asyncio.run(client.fetch_catalog())
    asyncio.run(client.aclose())
    assert stream.chunks_requested == 2
    assert stream.completed is False
    assert stream.closed is True


@pytest.mark.security
def test_client_limits_decoded_gzip_expansion_and_ignores_misleading_length() -> None:
    compressed = gzip.compress(b" " * (8 * 1024 * 1024))
    stream = InstrumentedStream(
        [compressed[index : index + 32] for index in range(0, len(compressed), 32)]
    )
    client = make_client(
        lambda _: httpx.Response(
            200,
            headers={
                "content-type": "application/json",
                "content-encoding": "gzip",
                "content-length": "10",
            },
            stream=stream,
        ),
        KEV_MAX_RESPONSE_BYTES=1024 * 1024,
    )
    with pytest.raises(KEVResponseTooLargeError):
        asyncio.run(client.fetch_catalog())
    asyncio.run(client.aclose())
    assert stream.completed is False
    assert stream.closed is True


@pytest.mark.security
@pytest.mark.parametrize(
    ("body", "content_type"),
    [
        (b"not-json", "application/json"),
        (b"\xff", "application/json"),
        (encoded(payload()), "text/html"),
    ],
)
def test_client_rejects_corrupt_non_utf8_and_wrong_content_type(
    body: bytes, content_type: str
) -> None:
    client = make_client(
        lambda _: httpx.Response(
            200, content=body, headers={"content-type": content_type}
        )
    )
    with pytest.raises(KEVInvalidResponseError):
        asyncio.run(client.fetch_catalog())
    asyncio.run(client.aclose())


@pytest.mark.security
@pytest.mark.parametrize("declared", ["invalid", "-1", "99999999"])
def test_client_rejects_invalid_or_oversized_declared_length_without_reading(
    declared: str,
) -> None:
    stream = InstrumentedStream([encoded(payload())])
    client = make_client(
        lambda _: httpx.Response(
            200,
            headers={
                "content-type": "application/json",
                "content-length": declared,
            },
            stream=stream,
        )
    )
    with pytest.raises(KEVInvalidResponseError):
        asyncio.run(client.fetch_catalog())
    asyncio.run(client.aclose())
    assert stream.chunks_requested == 0
    assert stream.closed is True


@pytest.mark.security
def test_interrupted_body_is_typed_and_closed() -> None:
    stream = InstrumentedStream(
        [b"{", b"unexpected"],
        fail_before_chunk=1,
    )
    client = make_client(
        lambda _: httpx.Response(
            200, headers={"content-type": "application/json"}, stream=stream
        )
    )
    with pytest.raises(KEVUnavailableError, match="interrupted"):
        asyncio.run(client.fetch_catalog())
    asyncio.run(client.aclose())
    assert stream.chunks_requested == 1
    assert stream.completed is False
    assert stream.closed is True


@pytest.mark.security
def test_client_rejects_excessive_json_depth_and_entry_count_before_contract() -> None:
    nested: object = "value"
    for _ in range(20):
        nested = {"nested": nested}
    deep = payload([])
    deep["extension"] = nested
    client = make_client(
        lambda _: httpx.Response(
            200, json=deep, headers={"content-type": "application/json"}
        )
    )
    with pytest.raises(KEVInvalidResponseError, match="depth"):
        asyncio.run(client.fetch_catalog())
    asyncio.run(client.aclose())

    too_many = payload([entry(), entry("CVE-2099-9998")])
    client = make_client(
        lambda _: httpx.Response(
            200, json=too_many, headers={"content-type": "application/json"}
        ),
        KEV_MAX_ENTRIES=1,
    )
    with pytest.raises(KEVInvalidResponseError, match="entry limit"):
        asyncio.run(client.fetch_catalog())
    asyncio.run(client.aclose())


@pytest.mark.security
@pytest.mark.parametrize(
    ("status_code", "error"),
    [
        (301, KEVInvalidResponseError),
        (403, KEVUnavailableError),
        (404, KEVInvalidResponseError),
        (429, KEVRateLimitError),
        (500, KEVUnavailableError),
    ],
)
def test_client_maps_http_errors_and_closes_response(
    status_code: int, error: type[Exception]
) -> None:
    stream = InstrumentedStream([b"secret"])
    client = make_client(lambda _: httpx.Response(status_code, stream=stream))
    with pytest.raises(error):
        asyncio.run(client.fetch_catalog())
    asyncio.run(client.aclose())
    assert stream.chunks_requested == 0
    assert stream.closed is True


@pytest.mark.security
def test_client_retry_budget_is_finite() -> None:
    calls = 0
    delays: list[float] = []

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503)

    async def sleep(delay: float) -> None:
        delays.append(delay)

    client = KEVClient(
        settings(KEV_MAX_RETRIES=2),
        transport=httpx.MockTransport(handler),
        sleep=sleep,
        random_source=lambda: 0,
    )
    with pytest.raises(KEVUnavailableError):
        asyncio.run(client.fetch_catalog())
    asyncio.run(client.aclose())
    assert calls == 3
    assert delays == [0.5, 1.0]


@pytest.mark.security
def test_client_cancellation_during_retry_backoff_is_propagated() -> None:
    async def exercise() -> None:
        backoff_started = asyncio.Event()
        never_release = asyncio.Event()
        stream = InstrumentedStream([b"private"])

        async def sleep(_: float) -> None:
            backoff_started.set()
            await never_release.wait()

        client = KEVClient(
            settings(KEV_MAX_RETRIES=2),
            transport=httpx.MockTransport(lambda _: httpx.Response(503, stream=stream)),
            sleep=sleep,
            random_source=lambda: 0,
        )
        task = asyncio.create_task(client.fetch_catalog())
        await backoff_started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert stream.closed is True
        assert client._concurrency._value == settings().KEV_MAX_CONCURRENCY
        await client.aclose()

    asyncio.run(exercise())


@pytest.mark.security
def test_client_total_deadline_and_cancellation_close_resources() -> None:
    async def slow_handler(_: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.05)
        return httpx.Response(200, json=payload())

    client = make_client(slow_handler, KEV_TOTAL_DEADLINE_SECONDS=0.01)
    with pytest.raises(KEVTimeoutError):
        asyncio.run(client.fetch_catalog())
    asyncio.run(client.aclose())

    wait = asyncio.Event()
    stream = InstrumentedStream([encoded(payload())], wait=wait)
    client = make_client(
        lambda _: httpx.Response(
            200, headers={"content-type": "application/json"}, stream=stream
        )
    )

    async def cancel() -> None:
        task = asyncio.create_task(client.fetch_catalog())
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await client.aclose()

    asyncio.run(cancel())
    assert stream.closed is True


@pytest.mark.integration
def test_api_status_and_unavailable_lookup_are_sanitized() -> None:
    application = create_app(settings())
    with TestClient(application) as client:
        status_response = client.get("/api/v1/intelligence/kev/status")
        lookup = client.get("/api/v1/intelligence/kev/CVE-2099-9999")
    assert status_response.status_code == 200
    assert status_response.json() == {
        "availability": "never_loaded",
        "catalog_version": None,
        "date_released": None,
        "fetched_at": None,
        "freshness_age_seconds": None,
        "count": None,
    }
    assert lookup.status_code == 503
    assert lookup.json() == {"detail": "CISA KEV catalog is not available."}


@pytest.mark.integration
@pytest.mark.parametrize("successful", [True, False])
def test_optional_startup_refresh_is_bounded_nonfatal_and_client_is_closed(
    successful: bool,
) -> None:
    result: FetchedKEVCatalog | Exception = (
        fetched() if successful else KEVUnavailableError("private provider detail")
    )
    kev_client = LifecycleKEVClient(result)
    application = create_app(
        settings(KEV_REFRESH_ON_STARTUP=True),
        kev_client_factory=lambda _: kev_client,  # type: ignore[arg-type,return-value]
    )
    with TestClient(application) as client:
        assert client.get("/api/v1/health/").status_code == 200
        status_body = client.get("/api/v1/intelligence/kev/status").json()
        assert status_body["availability"] == ("fresh" if successful else "unavailable")
        assert kev_client.closed is False
    assert kev_client.calls == 1
    assert application.state.kev_store._closed is True
    assert kev_client.closed is True


@pytest.mark.integration
def test_api_lookup_reads_snapshot_without_nvd_or_provider_fetch() -> None:
    application = create_app(settings())
    fetcher = StubFetcher(fetched())
    with TestClient(application) as client:
        store: KEVCatalogStore = application.state.kev_store
        asyncio.run(store.refresh(fetcher))
        listed = client.get("/api/v1/intelligence/kev/CVE-2099-9999")
        absent = client.get("/api/v1/intelligence/kev/CVE-2099-9998")
        status_response = client.get("/api/v1/intelligence/kev/status")
    assert listed.status_code == absent.status_code == 200
    assert listed.json()["presence"] == "listed"
    assert listed.json()["record"]["known_ransomware_campaign_use"] == "Unknown"
    assert listed.json()["record"]["due_date"] == "2026-11-10"
    assert absent.json()["presence"] == "not_listed"
    assert status_response.json()["count"] == 1
    assert fetcher.calls == 1


@pytest.mark.security
@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/intelligence/kev/cve-2021-44228",
        "/api/v1/intelligence/kev/CVE-2021-123",
        "/api/v1/intelligence/kev/https:%2F%2Fevil.test",
    ],
)
def test_api_rejects_invalid_cve_paths(path: str) -> None:
    with TestClient(create_app(settings())) as client:
        response = client.get(path)
    assert response.status_code in {404, 422}


@pytest.mark.contract
def test_openapi_documents_read_only_kev_contracts() -> None:
    with TestClient(create_app(settings())) as client:
        schema = client.get("/openapi.json").json()
    status_operation = schema["paths"]["/api/v1/intelligence/kev/status"]
    lookup = schema["paths"]["/api/v1/intelligence/kev/{cve_id}"]
    assert set(status_operation) == {"get"}
    assert set(lookup) == {"get"}
    assert {"422", "500", "503"} <= set(lookup["get"]["responses"])
    serialized = json.dumps({"status": status_operation, "lookup": lookup})
    assert (
        "source_url"
        not in status_operation["get"]["responses"]["200"]["content"][
            "application/json"
        ]["schema"]
    )
    assert "refresh" not in serialized.casefold()
