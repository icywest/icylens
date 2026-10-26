from __future__ import annotations

import asyncio
import gzip
import json
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, cast

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.config import Settings
from app.integrations.first_epss.client import (
    EPSSClient,
    EPSSInvalidResponseError,
    EPSSRateLimitError,
    EPSSResponseTooLargeError,
    EPSSTimeoutError,
    EPSSUnavailableError,
    RequestBudget,
    validate_epss_endpoint,
)
from app.integrations.first_epss.schemas import FIRSTEPSSResponse
from app.main import create_app
from app.schemas.epss import EPSSFreshness, EPSSLookupResult, EPSSLookupStatus
from app.services.epss_intelligence import EPSSIntelligenceService

FIXTURES = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 10, 25, 18, 0, tzinfo=timezone.utc)


def payload(name: str = "epss_high_synthetic.json") -> dict[str, Any]:
    return cast(
        dict[str, Any], json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    )


def settings(**updates: object) -> Settings:
    values: dict[str, object] = {
        "APP_ENV": "testing",
        "EPSS_MAX_RETRIES": 0,
        "EPSS_REQUESTS_PER_WINDOW": 20,
        "KEV_REFRESH_ON_STARTUP": False,
        "_env_file": None,
    }
    values.update(updates)
    return Settings(**values)  # type: ignore[arg-type]


def client(handler: Any, **updates: object) -> EPSSClient:
    return EPSSClient(settings(**updates), transport=httpx.MockTransport(handler))


class InstrumentedStream(httpx.AsyncByteStream):
    def __init__(
        self,
        chunks: list[bytes],
        *,
        fail_at: int | None = None,
        wait: asyncio.Event | None = None,
    ) -> None:
        self.chunks = chunks
        self.fail_at = fail_at
        self.wait = wait
        self.requested = 0
        self.completed = False
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        if self.wait is not None:
            await self.wait.wait()
        for index, chunk in enumerate(self.chunks):
            if index == self.fail_at:
                raise httpx.ReadError("synthetic interruption")
            self.requested += 1
            yield chunk
        self.completed = True

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.contract
@pytest.mark.parametrize(
    ("score", "percentile"),
    [
        ("0", "0"),
        ("1", "1"),
        ("0.0000000000000000001", "0.9999999999999999999"),
        (0.25, 0.75),
    ],
)
def test_decimal_boundaries_and_precision_are_preserved(
    score: object, percentile: object
) -> None:
    document = payload()
    document["data"][0]["epss"] = score
    document["data"][0]["percentile"] = percentile
    parsed = FIRSTEPSSResponse.model_validate(document)
    assert parsed.data[0].epss == Decimal(str(score))
    assert parsed.data[0].percentile == Decimal(str(percentile))


@pytest.mark.contract
@pytest.mark.parametrize(
    "invalid", ["-0.1", "1.1", "NaN", "Infinity", "-Infinity", "nope", True]
)
def test_invalid_probability_values_are_rejected(invalid: object) -> None:
    document = payload()
    document["data"][0]["epss"] = invalid
    with pytest.raises(ValidationError):
        FIRSTEPSSResponse.model_validate(document)


@pytest.mark.contract
@pytest.mark.parametrize(
    "mutation",
    ["status", "status-code", "total", "offset", "limit", "duplicate", "date"],
)
def test_contradictory_provider_envelopes_are_rejected(mutation: str) -> None:
    document = payload()
    if mutation == "status":
        document["status"] = "ERROR"
    elif mutation == "status-code":
        document["status-code"] = 500
    elif mutation == "total":
        document["total"] = 0
    elif mutation == "offset":
        document["offset"] = 1
    elif mutation == "limit":
        document["limit"] = 0
    elif mutation == "duplicate":
        document["data"].append(document["data"][0].copy())
        document["total"] = 2
    else:
        document["data"][0]["date"] = "not-a-date"
    with pytest.raises((ValidationError, ValueError)):
        FIRSTEPSSResponse.model_validate(document).ensure_point_query()


@pytest.mark.contract
def test_unknown_provider_metadata_is_forward_compatible() -> None:
    document = payload()
    document["future-provider-field"] = {"opaque": True}
    document["data"][0]["future-record-field"] = "ignored"
    assert FIRSTEPSSResponse.model_validate(document).total == 1


@pytest.mark.security
@pytest.mark.parametrize(
    "endpoint",
    [
        "http://api.first.org/data/v1/epss",
        "https://evil.test/data/v1/epss",
        "https://api.first.org.evil.test/data/v1/epss",
        "https://api.first.org/data/v1/epss?scope=all",
        "https://user:secret@api.first.org/data/v1/epss",
        "https://api.first.org/data/v1/epss/extra",
    ],
)
def test_only_exact_official_endpoint_is_allowed(endpoint: str) -> None:
    with pytest.raises(ValueError, match="approved HTTPS endpoint"):
        validate_epss_endpoint(endpoint)


@pytest.mark.security
def test_client_uses_fixed_query_tls_and_safe_transport() -> None:
    observed: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return httpx.Response(
            200, json=payload(), headers={"content-type": "application/json"}
        )

    current = client(handler)
    result = asyncio.run(current.fetch_cve("cve-2021-44228"))
    asyncio.run(current.aclose())
    assert result.total == 1
    assert observed[0].url == httpx.URL(
        "https://api.first.org/data/v1/epss?cve=CVE-2021-44228"
    )
    assert current._http.follow_redirects is False
    assert current._http.trust_env is False


@pytest.mark.security
def test_tls_verification_is_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    class StubAsyncClient:
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)

    monkeypatch.setattr(
        "app.integrations.first_epss.client.httpx.AsyncClient", StubAsyncClient
    )
    EPSSClient(settings())
    assert captured["verify"] is True
    assert captured["follow_redirects"] is False
    assert captured["trust_env"] is False


@pytest.mark.security
@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(302, headers={"location": "https://evil.test"}),
        httpx.Response(200, text="<html>", headers={"content-type": "text/html"}),
        httpx.Response(200, content=b"{", headers={"content-type": "application/json"}),
        httpx.Response(200, json={}, headers={"content-type": "application/json"}),
    ],
)
def test_redirect_html_corrupt_json_and_schema_errors_are_rejected(
    response: httpx.Response,
) -> None:
    current = client(lambda _: response)
    with pytest.raises(EPSSInvalidResponseError):
        asyncio.run(current.fetch_cve("CVE-2021-44228"))
    asyncio.run(current.aclose())


@pytest.mark.security
def test_declared_and_streamed_size_limits_close_early() -> None:
    declared_stream = InstrumentedStream([b"{}"])
    declared = client(
        lambda _: httpx.Response(
            200,
            stream=declared_stream,
            headers={"content-type": "application/json", "content-length": "2048"},
        ),
        EPSS_MAX_RESPONSE_BYTES=1024,
    )
    with pytest.raises(EPSSResponseTooLargeError):
        asyncio.run(declared.fetch_cve("CVE-2021-44228"))
    asyncio.run(declared.aclose())
    assert declared_stream.requested == 0 and declared_stream.closed

    actual_stream = InstrumentedStream([b"x" * 512] * 8)
    actual = client(
        lambda _: httpx.Response(
            200,
            stream=actual_stream,
            headers={"content-type": "application/json", "content-length": "1"},
        ),
        EPSS_MAX_RESPONSE_BYTES=1024,
    )
    with pytest.raises(EPSSResponseTooLargeError):
        asyncio.run(actual.fetch_cve("CVE-2021-44228"))
    asyncio.run(actual.aclose())
    assert actual_stream.requested == 3
    assert actual_stream.completed is False and actual_stream.closed


@pytest.mark.security
def test_gzip_limit_counts_decoded_bytes_and_aborts() -> None:
    compressed = gzip.compress(b"x" * (64 * 1024))
    stream = InstrumentedStream(
        [compressed[index : index + 8] for index in range(0, len(compressed), 8)]
    )
    current = client(
        lambda _: httpx.Response(
            200,
            stream=stream,
            headers={
                "content-type": "application/json",
                "content-encoding": "gzip",
                "content-length": str(len(compressed)),
            },
        ),
        EPSS_MAX_RESPONSE_BYTES=1024,
    )
    with pytest.raises(EPSSResponseTooLargeError):
        asyncio.run(current.fetch_cve("CVE-2021-44228"))
    asyncio.run(current.aclose())
    assert stream.completed is False and stream.closed


@pytest.mark.security
@pytest.mark.parametrize("length", ["invalid", "-1"])
def test_invalid_content_length_is_rejected(length: str) -> None:
    current = client(
        lambda _: httpx.Response(
            200,
            content=b"{}",
            headers={"content-type": "application/json", "content-length": length},
        )
    )
    with pytest.raises(EPSSInvalidResponseError, match="Content-Length"):
        asyncio.run(current.fetch_cve("CVE-2021-44228"))
    asyncio.run(current.aclose())


@pytest.mark.security
def test_interrupted_and_corrupt_compressed_streams_are_closed() -> None:
    interrupted_stream = InstrumentedStream([b"{", b"}"], fail_at=1)
    interrupted = client(
        lambda _: httpx.Response(
            200,
            stream=interrupted_stream,
            headers={"content-type": "application/json"},
        )
    )
    with pytest.raises(EPSSUnavailableError):
        asyncio.run(interrupted.fetch_cve("CVE-2021-44228"))
    asyncio.run(interrupted.aclose())
    assert interrupted_stream.closed

    corrupt_stream = InstrumentedStream([b"invalid gzip"])
    corrupt = client(
        lambda _: httpx.Response(
            200,
            stream=corrupt_stream,
            headers={
                "content-type": "application/json",
                "content-encoding": "gzip",
            },
        )
    )
    with pytest.raises(EPSSInvalidResponseError):
        asyncio.run(corrupt.fetch_cve("CVE-2021-44228"))
    asyncio.run(corrupt.aclose())
    assert corrupt_stream.closed


@pytest.mark.unit
@pytest.mark.parametrize(
    ("status_code", "error"),
    [
        (403, EPSSUnavailableError),
        (418, EPSSInvalidResponseError),
        (429, EPSSRateLimitError),
        (503, EPSSUnavailableError),
    ],
)
def test_http_failures_are_typed(status_code: int, error: type[Exception]) -> None:
    current = client(lambda _: httpx.Response(status_code))
    with pytest.raises(error):
        asyncio.run(current.fetch_cve("CVE-2021-44228"))
    asyncio.run(current.aclose())


@pytest.mark.unit
def test_transport_timeout_and_retry_after_are_bounded() -> None:
    timeout_client = client(
        lambda request: (_ for _ in ()).throw(
            httpx.ReadTimeout("slow", request=request)
        )
    )
    with pytest.raises(EPSSTimeoutError):
        asyncio.run(timeout_client.fetch_cve("CVE-2021-44228"))
    asyncio.run(timeout_client.aclose())

    calls = 0
    delays: list[float] = []

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(429, headers={"retry-after": "999"})

    async def record(delay: float) -> None:
        delays.append(delay)

    retrying = EPSSClient(
        settings(EPSS_MAX_RETRIES=2, EPSS_MAX_RETRY_AFTER_SECONDS=3),
        transport=httpx.MockTransport(handler),
        sleep=record,
    )
    with pytest.raises(EPSSRateLimitError):
        asyncio.run(retrying.fetch_cve("CVE-2021-44228"))
    asyncio.run(retrying.aclose())
    assert calls == 3 and delays == [3.0, 3.0]


@pytest.mark.unit
def test_request_budget_expires_and_each_retry_consumes_budget() -> None:
    tick = 100.0
    budget = RequestBudget(1, 30, clock=lambda: tick)
    assert asyncio.run(budget.try_acquire()) is True
    assert asyncio.run(budget.try_acquire()) is False
    tick = 131.0
    assert asyncio.run(budget.try_acquire()) is True

    async def no_sleep(_: float) -> None:
        return None

    current = EPSSClient(
        settings(EPSS_MAX_RETRIES=1),
        transport=httpx.MockTransport(lambda _: httpx.Response(503)),
        sleep=no_sleep,
        budget=RequestBudget(1, 30),
    )
    with pytest.raises(EPSSRateLimitError, match="local"):
        asyncio.run(current.fetch_cve("CVE-2021-44228"))
    asyncio.run(current.aclose())


@pytest.mark.security
def test_deadline_covers_capacity_wait_and_stream_cancellation_closes() -> None:
    async def exercise() -> None:
        release = asyncio.Event()
        stream = InstrumentedStream([json.dumps(payload()).encode()], wait=release)
        current = client(
            lambda _: httpx.Response(
                200, stream=stream, headers={"content-type": "application/json"}
            ),
            EPSS_TOTAL_DEADLINE_SECONDS=0.01,
        )
        with pytest.raises(EPSSTimeoutError):
            await current.fetch_cve("CVE-2021-44228")
        assert stream.closed
        await current._concurrency.acquire()
        try:
            with pytest.raises(EPSSTimeoutError):
                await current.fetch_cve("CVE-2021-44228")
        finally:
            current._concurrency.release()
        await current.aclose()

    asyncio.run(exercise())


@pytest.mark.security
def test_explicit_cancellation_propagates_and_closes_response() -> None:
    async def exercise() -> None:
        release = asyncio.Event()
        stream = InstrumentedStream([json.dumps(payload()).encode()], wait=release)
        current = client(
            lambda _: httpx.Response(
                200, stream=stream, headers={"content-type": "application/json"}
            )
        )
        task = asyncio.create_task(current.fetch_cve("CVE-2021-44228"))
        for _ in range(10):
            await asyncio.sleep(0)
            if current._concurrency._value == 1:
                break
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert stream.closed
        assert current._concurrency._value == 2
        await current.aclose()

    asyncio.run(exercise())


class StubEPSSClient:
    def __init__(
        self,
        responses: list[FIRSTEPSSResponse] | None = None,
        error: Exception | None = None,
        gate: asyncio.Event | None = None,
    ) -> None:
        self.responses = responses or [FIRSTEPSSResponse.model_validate(payload())]
        self.error = error
        self.gate = gate
        self.calls: list[str] = []
        self.closed = False

    async def fetch_cve(self, cve_id: str) -> FIRSTEPSSResponse:
        self.calls.append(cve_id)
        if self.gate is not None:
            await self.gate.wait()
        if self.error is not None:
            raise self.error
        return self.responses[min(len(self.calls) - 1, len(self.responses) - 1)]

    async def aclose(self) -> None:
        self.closed = True


class LifecycleEPSSClient:
    def __init__(self, *, error: Exception | None = None) -> None:
        self.error = error
        self.release = asyncio.Event()
        self.started = asyncio.Event()
        self.cancelled = asyncio.Event()
        self.calls: list[str] = []
        self.cancelled_cves: list[str] = []
        self.closed = False

    async def fetch_cve(self, cve_id: str) -> FIRSTEPSSResponse:
        self.calls.append(cve_id)
        self.started.set()
        try:
            await self.release.wait()
        except asyncio.CancelledError:
            self.cancelled_cves.append(cve_id)
            self.cancelled.set()
            raise
        if self.error is not None:
            raise self.error
        document = payload()
        document["data"][0]["cve"] = cve_id
        return FIRSTEPSSResponse.model_validate(document)

    async def aclose(self) -> None:
        self.closed = True


def service(
    stub: StubEPSSClient,
    *,
    now: datetime = NOW,
    clock: Any = lambda: 100.0,
    **updates: object,
) -> EPSSIntelligenceService:
    return EPSSIntelligenceService(
        settings(**updates),
        stub,
        now=lambda: now,
        clock=clock,
    )


def lifecycle_service(client: LifecycleEPSSClient) -> EPSSIntelligenceService:
    return EPSSIntelligenceService(
        settings(),
        client,
        now=lambda: NOW,
        clock=lambda: 100.0,
    )


@pytest.mark.contract
def test_service_normalizes_available_and_not_scored_without_fabrication() -> None:
    available = asyncio.run(service(StubEPSSClient()).lookup("cve-2021-44228"))
    assert available.status is EPSSLookupStatus.AVAILABLE
    assert available.score == Decimal("0.999990000")
    assert available.percentile == Decimal("1.000000000")
    assert available.freshness is EPSSFreshness.CURRENT
    assert available.provenance.model_version is None
    assert available.provenance.api_version == "1.0"

    empty = FIRSTEPSSResponse.model_validate(payload("epss_empty_synthetic.json"))
    missing = asyncio.run(service(StubEPSSClient([empty])).lookup("CVE-2021-44228"))
    assert missing.status is EPSSLookupStatus.NOT_SCORED
    assert missing.score is None and missing.percentile is None
    assert missing.freshness is EPSSFreshness.UNAVAILABLE


@pytest.mark.contract
def test_canonical_contract_rejects_inconsistent_freshness_and_provenance() -> None:
    record = asyncio.run(service(StubEPSSClient()).lookup("CVE-2021-44228"))
    inconsistent = record.model_dump()
    inconsistent["freshness"] = "unavailable"
    with pytest.raises(ValidationError, match="dated freshness"):
        EPSSLookupResult.model_validate(inconsistent)
    inconsistent = record.model_dump()
    inconsistent["provenance"]["source_score_date"] = "2026-10-24"
    with pytest.raises(ValidationError, match="must match"):
        EPSSLookupResult.model_validate(inconsistent)


@pytest.mark.contract
@pytest.mark.parametrize(
    ("score_date", "freshness"),
    [
        ("2026-10-24", EPSSFreshness.CURRENT),
        ("2026-10-23", EPSSFreshness.STALE),
        ("2026-10-18", EPSSFreshness.STALE),
        ("2026-10-17", EPSSFreshness.HISTORICAL),
    ],
)
def test_freshness_policy_uses_score_date(
    score_date: str, freshness: EPSSFreshness
) -> None:
    document = payload()
    document["data"][0]["date"] = score_date
    stub = StubEPSSClient([FIRSTEPSSResponse.model_validate(document)])
    assert asyncio.run(service(stub).lookup("CVE-2021-44228")).freshness is freshness


@pytest.mark.contract
def test_future_date_and_mismatched_identity_are_rejected() -> None:
    future = payload()
    future["data"][0]["date"] = "2026-10-26"
    wrong = payload()
    wrong["data"][0]["cve"] = "CVE-2022-0001"
    for document in (future, wrong):
        current = service(StubEPSSClient([FIRSTEPSSResponse.model_validate(document)]))
        with pytest.raises(EPSSInvalidResponseError):
            asyncio.run(current.lookup("CVE-2021-44228"))


@pytest.mark.unit
def test_cache_hit_ttl_expiry_eviction_and_newer_score() -> None:
    tick = 100.0
    first = FIRSTEPSSResponse.model_validate(payload("epss_low_synthetic.json"))
    second = FIRSTEPSSResponse.model_validate(payload("epss_high_synthetic.json"))
    stub = StubEPSSClient([first, second])
    current = service(
        stub,
        clock=lambda: tick,
        EPSS_CACHE_TTL_SECONDS=10,
        EPSS_CACHE_MAX_ENTRIES=1,
    )
    assert asyncio.run(current.lookup("CVE-2021-44228")).score == Decimal("0.000010000")
    assert asyncio.run(current.lookup("CVE-2021-44228")).score == Decimal("0.000010000")
    assert len(stub.calls) == 1
    tick = 111.0
    assert asyncio.run(current.lookup("CVE-2021-44228")).score == Decimal("0.999990000")
    assert len(stub.calls) == 2

    other = payload()
    other["data"][0]["cve"] = "CVE-2022-0001"
    stub.responses.append(FIRSTEPSSResponse.model_validate(other))
    asyncio.run(current.lookup("CVE-2022-0001"))
    assert list(current._cache) == ["CVE-2022-0001"]


@pytest.mark.unit
def test_cache_coalesces_identical_requests_but_not_different_cves() -> None:
    async def exercise() -> None:
        gate = asyncio.Event()
        stub = StubEPSSClient(gate=gate)
        current = service(stub)
        same = [
            asyncio.create_task(current.lookup("CVE-2021-44228")) for _ in range(10)
        ]
        for _ in range(10):
            await asyncio.sleep(0)
            if stub.calls:
                break
        assert stub.calls == ["CVE-2021-44228"]
        gate.set()
        await asyncio.gather(*same)
        assert len(stub.calls) == 1

        other_document = payload()
        other_document["data"][0]["cve"] = "CVE-2022-0001"
        stub.responses.append(FIRSTEPSSResponse.model_validate(other_document))
        await current.lookup("CVE-2022-0001")
        assert stub.calls[-1] == "CVE-2022-0001"

    asyncio.run(exercise())


@pytest.mark.security
def test_one_cancelled_waiter_does_not_cancel_a_shared_fetch() -> None:
    async def exercise() -> None:
        provider = LifecycleEPSSClient()
        current = lifecycle_service(provider)
        first = asyncio.create_task(current.lookup("CVE-2021-44228"))
        await provider.started.wait()
        second = asyncio.create_task(current.lookup("CVE-2021-44228"))
        await asyncio.sleep(0)
        operation = current._inflight["CVE-2021-44228"]
        assert operation.active_waiters == 2

        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        assert operation.active_waiters == 1
        assert not operation.task.cancelled()
        assert provider.cancelled_cves == []

        provider.release.set()
        assert (await second).cve_id == "CVE-2021-44228"
        assert provider.calls == ["CVE-2021-44228"]
        assert current._inflight == {}

    asyncio.run(exercise())


@pytest.mark.security
def test_last_cancelled_waiter_cancels_collects_and_does_not_cache() -> None:
    async def exercise() -> None:
        provider = LifecycleEPSSClient()
        current = lifecycle_service(provider)
        first = asyncio.create_task(current.lookup("CVE-2021-44228"))
        second = asyncio.create_task(current.lookup("CVE-2021-44228"))
        await provider.started.wait()
        await asyncio.sleep(0)

        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        assert not provider.cancelled.is_set()
        second.cancel()
        with pytest.raises(asyncio.CancelledError):
            await second

        assert provider.cancelled.is_set()
        assert provider.cancelled_cves == ["CVE-2021-44228"]
        assert current._inflight == {}
        assert current._cache == {}
        assert [
            task for task in asyncio.all_tasks() if task is not asyncio.current_task()
        ] == []

    asyncio.run(exercise())


@pytest.mark.security
def test_distinct_cancelled_cves_release_saturated_client_capacity() -> None:
    async def exercise() -> None:
        release = asyncio.Event()
        started = asyncio.Event()
        streams: list[InstrumentedStream] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            document = payload()
            document["data"][0]["cve"] = request.url.params["cve"]
            stream = InstrumentedStream([json.dumps(document).encode()], wait=release)
            streams.append(stream)
            started.set()
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                stream=stream,
            )

        provider = EPSSClient(
            settings(EPSS_MAX_CONCURRENCY=1),
            transport=httpx.MockTransport(handler),
        )
        current = EPSSIntelligenceService(
            settings(), provider, now=lambda: NOW, clock=lambda: 100.0
        )
        cves = tuple(f"CVE-2026-{index:04d}" for index in range(1000, 1005))
        waiters = [asyncio.create_task(current.lookup(cve)) for cve in cves]
        await started.wait()
        for _ in range(10):
            if len(current._inflight) == len(cves):
                break
            await asyncio.sleep(0)
        assert len(current._inflight) == len(cves)
        assert provider._concurrency._value == 0

        for waiter in waiters:
            waiter.cancel()
        results = await asyncio.gather(*waiters, return_exceptions=True)
        assert all(isinstance(item, asyncio.CancelledError) for item in results)
        assert current._inflight == {}
        assert current._cache == {}
        assert provider._concurrency._value == 1
        assert streams and streams[0].closed
        assert [
            task for task in asyncio.all_tasks() if task is not asyncio.current_task()
        ] == []
        await provider.aclose()

    asyncio.run(exercise())


@pytest.mark.security
def test_cancelled_operation_is_not_reused_by_a_rejoining_waiter() -> None:
    class SlowCancellationClient(LifecycleEPSSClient):
        def __init__(self) -> None:
            super().__init__()
            self.finish_cancellation = asyncio.Event()

        async def fetch_cve(self, cve_id: str) -> FIRSTEPSSResponse:
            self.calls.append(cve_id)
            self.started.set()
            if len(self.calls) == 1:
                try:
                    await self.release.wait()
                except asyncio.CancelledError:
                    self.cancelled_cves.append(cve_id)
                    self.cancelled.set()
                    await self.finish_cancellation.wait()
                    raise
            document = payload()
            document["data"][0]["cve"] = cve_id
            return FIRSTEPSSResponse.model_validate(document)

    async def exercise() -> None:
        provider = SlowCancellationClient()
        current = lifecycle_service(provider)
        abandoned = asyncio.create_task(current.lookup("CVE-2021-44228"))
        await provider.started.wait()
        abandoned.cancel()
        await provider.cancelled.wait()

        replacement = asyncio.create_task(current.lookup("CVE-2021-44228"))
        result = await replacement
        assert result.cve_id == "CVE-2021-44228"
        assert provider.calls == ["CVE-2021-44228", "CVE-2021-44228"]

        provider.finish_cancellation.set()
        with pytest.raises(asyncio.CancelledError):
            await abandoned
        assert current._inflight == {}

    asyncio.run(exercise())


@pytest.mark.security
def test_provider_completion_and_last_waiter_cancellation_race_is_collected() -> None:
    async def exercise() -> None:
        provider = LifecycleEPSSClient()
        current = lifecycle_service(provider)
        waiter = asyncio.create_task(current.lookup("CVE-2021-44228"))
        await provider.started.wait()
        provider.release.set()
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        assert current._inflight == {}
        assert len(current._cache) <= 1
        assert [
            task for task in asyncio.all_tasks() if task is not asyncio.current_task()
        ] == []

    asyncio.run(exercise())


@pytest.mark.security
def test_provider_error_near_cancellation_is_retrieved_and_cleaned() -> None:
    async def exercise() -> None:
        provider = LifecycleEPSSClient(error=EPSSUnavailableError("offline"))
        current = lifecycle_service(provider)
        waiter = asyncio.create_task(current.lookup("CVE-2021-44228"))
        await provider.started.wait()
        provider.release.set()
        await asyncio.sleep(0)
        waiter.cancel()
        result = await asyncio.gather(waiter, return_exceptions=True)
        assert isinstance(result[0], (asyncio.CancelledError, EPSSUnavailableError))
        assert current._inflight == {}
        assert current._cache == {}
        assert [
            task for task in asyncio.all_tasks() if task is not asyncio.current_task()
        ] == []

    asyncio.run(exercise())


@pytest.mark.security
def test_lifespan_shutdown_cancels_service_tasks_before_closing_client() -> None:
    async def exercise() -> None:
        provider = LifecycleEPSSClient()
        application = create_app(
            settings(),
            epss_client_factory=lambda _: provider,  # type: ignore[arg-type,return-value]
        )
        waiter: asyncio.Task[EPSSLookupResult]
        async with application.router.lifespan_context(application):
            current = cast(EPSSIntelligenceService, application.state.epss_service)
            waiter = asyncio.create_task(current.lookup("CVE-2021-44228"))
            await provider.started.wait()
            assert provider.closed is False
        await asyncio.gather(waiter, return_exceptions=True)
        assert provider.cancelled.is_set()
        assert provider.closed is True
        assert current._inflight == {}
        assert [
            task for task in asyncio.all_tasks() if task is not asyncio.current_task()
        ] == []

    asyncio.run(exercise())


@pytest.mark.unit
def test_failures_are_not_cached() -> None:
    stub = StubEPSSClient(error=EPSSUnavailableError("offline"))
    current = service(stub)
    for _ in range(2):
        with pytest.raises(EPSSUnavailableError):
            asyncio.run(current.lookup("CVE-2021-44228"))
    assert len(stub.calls) == 2 and not current._cache


def api_client(stub: StubEPSSClient) -> TestClient:
    application = create_app(
        settings(),
        epss_client_factory=lambda _: stub,  # type: ignore[arg-type,return-value]
    )
    return TestClient(application)


@pytest.mark.integration
def test_endpoint_returns_exact_contract_and_closes_client() -> None:
    stub = StubEPSSClient()
    with api_client(stub) as test_client:
        response = test_client.get("/api/v1/intelligence/epss/CVE-2021-44228")
        assert test_client.get("/api/v1/health/").status_code == 200
    assert stub.closed is True
    assert response.status_code == 200
    body = response.json()
    assert set(body) == set(EPSSLookupResult.model_fields)
    assert body["score"] == "0.999990000"
    assert body["percentile"] == "1.000000000"
    assert body["provenance"]["model_version"] is None


@pytest.mark.integration
@pytest.mark.parametrize(
    ("error", "status_code"),
    [
        (EPSSRateLimitError("limited"), 429),
        (EPSSInvalidResponseError("bad private response"), 502),
        (EPSSUnavailableError("offline"), 503),
        (EPSSTimeoutError("slow"), 504),
        (RuntimeError("private secret"), 500),
    ],
)
def test_endpoint_maps_sanitized_errors(error: Exception, status_code: int) -> None:
    with api_client(StubEPSSClient(error=error)) as test_client:
        response = test_client.get("/api/v1/intelligence/epss/CVE-2021-44228")
    assert response.status_code == status_code
    assert "private" not in response.text and "secret" not in response.text


@pytest.mark.security
@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/intelligence/epss/cve-2021-44228",
        "/api/v1/intelligence/epss/CVE-2021-123",
        "/api/v1/intelligence/epss/CVE-0000-1234",
        "/api/v1/intelligence/epss/https:%2F%2Fevil.test",
        "/api/v1/intelligence/epss/CVE-2021-44228%2F..%2Fhealth",
    ],
)
def test_endpoint_rejects_invalid_or_manipulated_paths(path: str) -> None:
    with api_client(StubEPSSClient()) as test_client:
        response = test_client.get(path)
    assert response.status_code in {404, 422}


@pytest.mark.contract
def test_openapi_documents_read_only_contract_and_error_taxonomy() -> None:
    with api_client(StubEPSSClient()) as test_client:
        schema = test_client.get("/openapi.json").json()
    operation = schema["paths"]["/api/v1/intelligence/epss/{cve_id}"]["get"]
    assert operation["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/EPSSLookupResult"
    }
    assert {"422", "429", "500", "502", "503", "504"} <= set(operation["responses"])
    assert "requestBody" not in operation
    assert "url" not in [item["name"] for item in operation["parameters"]]
