from __future__ import annotations

import asyncio
import gzip
import json
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.config import Settings
from app.integrations.nvd.client import (
    NVDClient,
    NVDInvalidResponseError,
    NVDNotFoundError,
    NVDRateLimitError,
    NVDResponseTooLargeError,
    NVDTimeoutError,
    NVDUnavailableError,
    RequestBudget,
    validate_nvd_endpoint,
)
from app.integrations.nvd.schemas import NVDResponse
from app.main import create_app
from app.schemas.vulnerability import VulnerabilityRecord, normalize_cve_id
from app.services.vulnerability_intelligence import normalize_nvd_response

FIXTURES = Path(__file__).parent / "fixtures"
RETRIEVED_AT = datetime(2026, 10, 25, 18, 0, tzinfo=timezone.utc)


class InstrumentedStream(httpx.AsyncByteStream):
    def __init__(
        self,
        chunks: list[bytes],
        *,
        fail_before_chunk: int | None = None,
        wait_before_first: asyncio.Event | None = None,
        iteration_started: asyncio.Event | None = None,
    ) -> None:
        self.chunks = chunks
        self.fail_before_chunk = fail_before_chunk
        self.wait_before_first = wait_before_first
        self.iteration_started = iteration_started
        self.chunks_requested = 0
        self.bytes_consumed = 0
        self.completed = False
        self.closed = False

    async def __aiter__(self):
        if self.iteration_started is not None:
            self.iteration_started.set()
        if self.wait_before_first is not None:
            await self.wait_before_first.wait()
        for index, chunk in enumerate(self.chunks):
            if self.fail_before_chunk == index:
                raise httpx.ReadError("interrupted test stream")
            self.chunks_requested += 1
            self.bytes_consumed += len(chunk)
            yield chunk
        self.completed = True

    async def aclose(self) -> None:
        self.closed = True


def fixture_payload(name: str = "nvd_cve_rich_synthetic.json") -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def nvd_settings(**updates: object) -> Settings:
    values: dict[str, object] = {
        "APP_ENV": "testing",
        "NVD_MAX_RETRIES": 0,
        "NVD_REQUESTS_PER_WINDOW": 20,
        "_env_file": None,
    }
    values.update(updates)
    return Settings(**values)  # type: ignore[arg-type]


def make_client(
    handler: Any,
    **settings_updates: object,
) -> NVDClient:
    return NVDClient(
        nvd_settings(**settings_updates),
        transport=httpx.MockTransport(handler),
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    "value",
    ["CVE-1999-0001", "CVE-2021-44228", "CVE-2026-1234567"],
)
def test_cve_identifier_accepts_standard_and_extended_sequences(value: str) -> None:
    assert normalize_cve_id(value) == value


@pytest.mark.unit
@pytest.mark.parametrize(
    "value",
    [
        "CVE-98-0001",
        "CVE-2021-123",
        "CVE-2021-1234/../../",
        "https://services.nvd.nist.gov/",
        "CVE-2021-１２３４",
    ],
)
def test_cve_identifier_rejects_malformed_and_path_values(value: str) -> None:
    with pytest.raises(ValueError):
        normalize_cve_id(value)


@pytest.mark.security
@pytest.mark.parametrize(
    "endpoint",
    [
        "http://services.nvd.nist.gov/rest/json/cves/2.0",
        "https://evil.test/rest/json/cves/2.0",
        "https://services.nvd.nist.gov.evil.test/rest/json/cves/2.0",
        "https://services.nvd.nist.gov/rest/json/cves/2.0?url=https://evil.test",
        "https://user:secret@services.nvd.nist.gov/rest/json/cves/2.0",
    ],
)
def test_only_exact_approved_nvd_endpoint_is_allowed(endpoint: str) -> None:
    with pytest.raises(ValueError, match="approved HTTPS endpoint"):
        validate_nvd_endpoint(endpoint)


@pytest.mark.security
def test_client_uses_safe_query_header_and_no_redirects() -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["request"] = request
        return httpx.Response(
            200,
            json=fixture_payload(),
            headers={"content-type": "application/json"},
        )

    client = make_client(handler, NVD_API_KEY="top-secret")
    response = asyncio.run(client.fetch_cve("CVE-2021-44228"))
    asyncio.run(client.aclose())

    request = captured["request"]
    assert response.totalResults == 1
    assert request.url.scheme == "https"
    assert request.url.host == "services.nvd.nist.gov"
    assert dict(request.url.params) == {"cveId": "CVE-2021-44228"}
    assert request.headers["apiKey"] == "top-secret"
    assert "top-secret" not in str(request.url)
    assert client._http.follow_redirects is False


@pytest.mark.security
def test_api_key_is_optional_and_secret_representation_is_redacted() -> None:
    captured_headers: httpx.Headers | None = None

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal captured_headers
        captured_headers = request.headers
        return httpx.Response(
            200,
            json={
                "resultsPerPage": 0,
                "startIndex": 0,
                "totalResults": 0,
                "vulnerabilities": [],
                "format": "NVD_CVE",
                "version": "2.0",
                "timestamp": "2026-10-25T12:00:00.000",
            },
            headers={"content-type": "application/json"},
        )

    settings = nvd_settings()
    assert settings.NVD_API_KEY is None
    client = NVDClient(settings, transport=httpx.MockTransport(handler))
    with pytest.raises(NVDNotFoundError):
        response = asyncio.run(client.fetch_cve("CVE-2021-0001"))
        normalize_nvd_response(response, "CVE-2021-0001", RETRIEVED_AT)
    asyncio.run(client.aclose())
    assert captured_headers is not None
    assert "apikey" not in captured_headers

    secret_settings = nvd_settings(NVD_API_KEY="never-log-me")
    assert "never-log-me" not in repr(secret_settings)


@pytest.mark.security
def test_tls_verification_is_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    class StubAsyncClient:
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)

    monkeypatch.setattr(
        "app.integrations.nvd.client.httpx.AsyncClient", StubAsyncClient
    )
    NVDClient(nvd_settings())
    assert captured["verify"] is True
    assert captured["follow_redirects"] is False
    assert captured["trust_env"] is False


@pytest.mark.unit
def test_client_rejects_redirect_html_corrupt_json_and_schema_errors() -> None:
    cases = [
        httpx.Response(302, headers={"location": "https://evil.test"}),
        httpx.Response(200, text="<html/>", headers={"content-type": "text/html"}),
        httpx.Response(200, content=b"{", headers={"content-type": "application/json"}),
        httpx.Response(200, json={}, headers={"content-type": "application/json"}),
    ]
    for response in cases:
        client = make_client(lambda _, current=response: current)
        with pytest.raises(NVDInvalidResponseError):
            asyncio.run(client.fetch_cve("CVE-2021-44228"))
        asyncio.run(client.aclose())


@pytest.mark.security
def test_client_enforces_declared_and_actual_response_limits() -> None:
    declared = make_client(
        lambda _: httpx.Response(
            200,
            content=b"{}",
            headers={"content-type": "application/json", "content-length": "2048"},
        ),
        NVD_MAX_RESPONSE_BYTES=1024,
    )
    with pytest.raises(NVDResponseTooLargeError):
        asyncio.run(declared.fetch_cve("CVE-2021-44228"))
    asyncio.run(declared.aclose())

    actual = make_client(
        lambda _: httpx.Response(
            200,
            content=b" " * 1025,
            headers={"content-type": "application/json"},
        ),
        NVD_MAX_RESPONSE_BYTES=1024,
    )
    with pytest.raises(NVDResponseTooLargeError):
        asyncio.run(actual.fetch_cve("CVE-2021-44228"))
    asyncio.run(actual.aclose())


@pytest.mark.security
def test_plain_oversized_stream_stops_early_and_closes() -> None:
    stream = InstrumentedStream([b"x" * 512 for _ in range(8)])
    client = make_client(
        lambda _: httpx.Response(
            200,
            headers={"content-type": "application/json"},
            stream=stream,
        ),
        NVD_MAX_RESPONSE_BYTES=1024,
    )

    with pytest.raises(NVDResponseTooLargeError):
        asyncio.run(client.fetch_cve("CVE-2021-44228"))
    asyncio.run(client.aclose())

    assert stream.chunks_requested == 3
    assert stream.bytes_consumed == 1536
    assert stream.completed is False
    assert stream.closed is True


@pytest.mark.security
@pytest.mark.parametrize(
    ("encoding", "compress"),
    [("gzip", gzip.compress), ("deflate", zlib.compress)],
)
def test_compression_limit_counts_decoded_bytes_and_stops_network_stream_early(
    encoding: str, compress: Any
) -> None:
    expanded_size = 64 * 1024
    compressed = compress(b"x" * expanded_size)
    chunks = [compressed[index : index + 8] for index in range(0, len(compressed), 8)]
    stream = InstrumentedStream(chunks)
    client = make_client(
        lambda _: httpx.Response(
            200,
            headers={
                "content-type": "application/json",
                "content-encoding": encoding,
                "content-length": str(len(compressed)),
            },
            stream=stream,
        ),
        NVD_MAX_RESPONSE_BYTES=1024,
    )

    with pytest.raises(NVDResponseTooLargeError):
        asyncio.run(client.fetch_cve("CVE-2021-44228"))
    asyncio.run(client.aclose())

    assert len(compressed) < 1024 < expanded_size
    assert stream.chunks_requested < len(chunks)
    assert stream.bytes_consumed < len(compressed)
    assert stream.completed is False
    assert stream.closed is True


@pytest.mark.security
def test_too_small_content_length_does_not_bypass_stream_limit() -> None:
    stream = InstrumentedStream([b"x" * 512 for _ in range(8)])
    client = make_client(
        lambda _: httpx.Response(
            200,
            headers={"content-type": "application/json", "content-length": "1"},
            stream=stream,
        ),
        NVD_MAX_RESPONSE_BYTES=1024,
    )

    with pytest.raises(NVDResponseTooLargeError):
        asyncio.run(client.fetch_cve("CVE-2021-44228"))
    asyncio.run(client.aclose())

    assert stream.completed is False
    assert stream.closed is True


@pytest.mark.security
def test_declared_oversize_rejects_without_reading_stream() -> None:
    stream = InstrumentedStream([b"{}"])
    client = make_client(
        lambda _: httpx.Response(
            200,
            headers={"content-type": "application/json", "content-length": "2048"},
            stream=stream,
        ),
        NVD_MAX_RESPONSE_BYTES=1024,
    )

    with pytest.raises(NVDResponseTooLargeError):
        asyncio.run(client.fetch_cve("CVE-2021-44228"))
    asyncio.run(client.aclose())

    assert stream.chunks_requested == 0
    assert stream.closed is True


@pytest.mark.security
def test_interrupted_stream_is_typed_and_closed() -> None:
    stream = InstrumentedStream(
        [b"{" * 512, b"x" * 512],
        fail_before_chunk=1,
    )
    client = make_client(
        lambda _: httpx.Response(
            200,
            headers={"content-type": "application/json"},
            stream=stream,
        )
    )

    with pytest.raises(NVDUnavailableError, match="interrupted"):
        asyncio.run(client.fetch_cve("CVE-2021-44228"))
    asyncio.run(client.aclose())

    assert stream.chunks_requested == 1
    assert stream.completed is False
    assert stream.closed is True


@pytest.mark.security
def test_corrupt_compressed_stream_is_invalid_and_closed() -> None:
    stream = InstrumentedStream([b"not-a-valid-gzip-stream"])
    client = make_client(
        lambda _: httpx.Response(
            200,
            headers={
                "content-type": "application/json",
                "content-encoding": "gzip",
            },
            stream=stream,
        )
    )

    with pytest.raises(NVDInvalidResponseError, match="content encoding"):
        asyncio.run(client.fetch_cve("CVE-2021-44228"))
    asyncio.run(client.aclose())

    assert stream.closed is True


@pytest.mark.security
def test_invalid_content_length_is_rejected() -> None:
    client = make_client(
        lambda _: httpx.Response(
            200,
            content=b"{}",
            headers={"content-type": "application/json", "content-length": "invalid"},
        )
    )
    with pytest.raises(NVDInvalidResponseError, match="Content-Length"):
        asyncio.run(client.fetch_cve("CVE-2021-44228"))
    asyncio.run(client.aclose())


@pytest.mark.unit
def test_timeout_and_transport_failures_are_typed() -> None:
    timeout_client = make_client(
        lambda request: (_ for _ in ()).throw(
            httpx.ReadTimeout("slow", request=request)
        )
    )
    with pytest.raises(NVDTimeoutError):
        asyncio.run(timeout_client.fetch_cve("CVE-2021-44228"))
    asyncio.run(timeout_client.aclose())

    transport_client = make_client(
        lambda request: (_ for _ in ()).throw(
            httpx.ConnectError("offline", request=request)
        )
    )
    with pytest.raises(NVDUnavailableError):
        asyncio.run(transport_client.fetch_cve("CVE-2021-44228"))
    asyncio.run(transport_client.aclose())


@pytest.mark.unit
def test_bounded_retries_honor_capped_retry_after() -> None:
    calls = 0
    delays: list[float] = []

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(429, headers={"retry-after": "999"})

    async def record_sleep(delay: float) -> None:
        delays.append(delay)

    client = NVDClient(
        nvd_settings(
            NVD_MAX_RETRIES=2,
            NVD_MAX_RETRY_AFTER_SECONDS=3,
            NVD_REQUESTS_PER_WINDOW=10,
        ),
        transport=httpx.MockTransport(handler),
        sleep=record_sleep,
    )
    with pytest.raises(NVDRateLimitError):
        asyncio.run(client.fetch_cve("CVE-2021-44228"))
    asyncio.run(client.aclose())
    assert calls == 3
    assert delays == [3.0, 3.0]


@pytest.mark.unit
@pytest.mark.parametrize(
    "failure", [httpx.ReadTimeout("slow"), httpx.ConnectError("offline")]
)
def test_transient_transport_failures_retry_once(failure: httpx.TransportError) -> None:
    calls = 0
    delays: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            failure.request = request
            raise failure
        return httpx.Response(
            200,
            json=fixture_payload(),
            headers={"content-type": "application/json"},
        )

    async def record_sleep(delay: float) -> None:
        delays.append(delay)

    client = NVDClient(
        nvd_settings(NVD_MAX_RETRIES=1),
        transport=httpx.MockTransport(handler),
        sleep=record_sleep,
        random_source=lambda: 0.0,
    )
    assert asyncio.run(client.fetch_cve("CVE-2021-44228")).totalResults == 1
    asyncio.run(client.aclose())
    assert calls == 2
    assert delays == [0.5]


@pytest.mark.unit
def test_5xx_retry_uses_backoff_without_retry_after() -> None:
    responses = iter(
        [
            httpx.Response(503),
            httpx.Response(
                200,
                json=fixture_payload(),
                headers={"content-type": "application/json"},
            ),
        ]
    )
    delays: list[float] = []

    async def record_sleep(delay: float) -> None:
        delays.append(delay)

    client = NVDClient(
        nvd_settings(NVD_MAX_RETRIES=1),
        transport=httpx.MockTransport(lambda _: next(responses)),
        sleep=record_sleep,
        random_source=lambda: 0.0,
    )
    asyncio.run(client.fetch_cve("CVE-2021-44228"))
    asyncio.run(client.aclose())
    assert delays == [0.5]


@pytest.mark.unit
def test_local_request_budget_and_unexpected_4xx_are_typed() -> None:
    valid_client = make_client(
        lambda _: httpx.Response(
            200,
            json=fixture_payload(),
            headers={"content-type": "application/json"},
        ),
        NVD_REQUESTS_PER_WINDOW=1,
    )
    asyncio.run(valid_client.fetch_cve("CVE-2021-44228"))
    with pytest.raises(NVDRateLimitError, match="local"):
        asyncio.run(valid_client.fetch_cve("CVE-2021-44228"))
    asyncio.run(valid_client.aclose())

    error_client = make_client(lambda _: httpx.Response(418))
    with pytest.raises(NVDInvalidResponseError, match="HTTP status"):
        asyncio.run(error_client.fetch_cve("CVE-2021-44228"))
    asyncio.run(error_client.aclose())


@pytest.mark.unit
def test_retry_after_parser_handles_dates_invalid_values_and_negative_seconds() -> None:
    client = make_client(lambda _: httpx.Response(500))
    assert client._parse_retry_after("not-a-date") is None
    assert client._parse_retry_after("-2") == 0.0
    assert client._parse_retry_after("Sun, 06 Nov 1994 08:49:37 GMT") == 0.0
    asyncio.run(client.aclose())


@pytest.mark.unit
def test_403_404_and_5xx_have_distinct_errors() -> None:
    cases = [
        (403, NVDUnavailableError),
        (404, NVDNotFoundError),
        (503, NVDUnavailableError),
    ]
    for status_code, expected in cases:
        client = make_client(lambda _, code=status_code: httpx.Response(code))
        with pytest.raises(expected):
            asyncio.run(client.fetch_cve("CVE-2021-44228"))
        asyncio.run(client.aclose())


@pytest.mark.unit
def test_request_budget_is_per_window_and_immediate() -> None:
    clock_value = 100.0
    budget = RequestBudget(2, 30.0, clock=lambda: clock_value)
    assert asyncio.run(budget.try_acquire()) is True
    assert asyncio.run(budget.try_acquire()) is True
    assert asyncio.run(budget.try_acquire()) is False
    clock_value = 131.0
    assert asyncio.run(budget.try_acquire()) is True


@pytest.mark.security
def test_total_deadline_includes_semaphore_wait_and_capacity_is_released() -> None:
    async def exercise() -> None:
        client = make_client(
            lambda _: httpx.Response(
                200,
                json=fixture_payload(),
                headers={"content-type": "application/json"},
            ),
            NVD_MAX_CONCURRENCY=1,
            NVD_TOTAL_DEADLINE_SECONDS=0.02,
        )
        await client._concurrency.acquire()
        try:
            with pytest.raises(NVDTimeoutError, match="total deadline"):
                await client.fetch_cve("CVE-2021-44228")
        finally:
            client._concurrency.release()

        assert (await client.fetch_cve("CVE-2021-44228")).totalResults == 1
        assert client._concurrency._value == 1
        await client.aclose()

    asyncio.run(exercise())


@pytest.mark.security
def test_total_deadline_interrupts_slow_stream_and_closes_it() -> None:
    async def exercise() -> None:
        never_release = asyncio.Event()
        stream = InstrumentedStream(
            [json.dumps(fixture_payload()).encode()],
            wait_before_first=never_release,
        )
        client = make_client(
            lambda _: httpx.Response(
                200,
                headers={"content-type": "application/json"},
                stream=stream,
            ),
            NVD_TOTAL_DEADLINE_SECONDS=0.02,
        )
        with pytest.raises(NVDTimeoutError, match="total deadline"):
            await client.fetch_cve("CVE-2021-44228")
        assert stream.chunks_requested == 0
        assert stream.closed is True
        assert client._concurrency._value == 2
        await client.aclose()

    asyncio.run(exercise())


@pytest.mark.security
def test_total_deadline_includes_retry_backoff() -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503, headers={"retry-after": "1"})

    client = make_client(
        handler,
        NVD_MAX_RETRIES=2,
        NVD_TOTAL_DEADLINE_SECONDS=0.02,
    )
    with pytest.raises(NVDTimeoutError, match="total deadline"):
        asyncio.run(client.fetch_cve("CVE-2021-44228"))
    asyncio.run(client.aclose())
    assert calls == 1


@pytest.mark.security
def test_external_cancellation_during_backoff_propagates_and_releases_capacity() -> (
    None
):
    async def exercise() -> None:
        backoff_started = asyncio.Event()
        never_release = asyncio.Event()
        stream = InstrumentedStream([])

        async def blocked_sleep(_: float) -> None:
            backoff_started.set()
            await never_release.wait()

        client = NVDClient(
            nvd_settings(NVD_MAX_RETRIES=1, NVD_MAX_CONCURRENCY=1),
            transport=httpx.MockTransport(lambda _: httpx.Response(503, stream=stream)),
            sleep=blocked_sleep,
        )
        task = asyncio.create_task(client.fetch_cve("CVE-2021-44228"))
        await backoff_started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert stream.closed is True
        assert client._concurrency._value == 1
        await client.aclose()

    asyncio.run(exercise())


@pytest.mark.security
def test_external_cancellation_during_stream_closes_and_releases_capacity() -> None:
    async def exercise() -> None:
        stream_started = asyncio.Event()
        never_release = asyncio.Event()
        stream = InstrumentedStream(
            [json.dumps(fixture_payload()).encode()],
            wait_before_first=never_release,
            iteration_started=stream_started,
        )
        client = make_client(
            lambda _: httpx.Response(
                200,
                headers={"content-type": "application/json"},
                stream=stream,
            ),
            NVD_MAX_CONCURRENCY=1,
        )
        task = asyncio.create_task(client.fetch_cve("CVE-2021-44228"))
        await stream_started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert stream.closed is True
        assert client._concurrency._value == 1
        await client.aclose()

    asyncio.run(exercise())


@pytest.mark.security
def test_concurrency_limit_allows_two_and_queues_excess_request() -> None:
    async def exercise() -> None:
        release_streams = asyncio.Event()
        payload = json.dumps(fixture_payload()).encode()
        streams: list[InstrumentedStream] = []
        calls = 0

        def handler(_: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            stream = InstrumentedStream(
                [payload],
                wait_before_first=release_streams,
            )
            streams.append(stream)
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                stream=stream,
            )

        client = make_client(
            handler,
            NVD_MAX_CONCURRENCY=2,
            NVD_TOTAL_DEADLINE_SECONDS=1,
        )
        tasks = [
            asyncio.create_task(client.fetch_cve("CVE-2021-44228")) for _ in range(3)
        ]
        for _ in range(20):
            if calls == 2:
                break
            await asyncio.sleep(0)
        assert calls == 2
        assert client._concurrency._value == 0
        assert tasks[2].done() is False

        release_streams.set()
        results = await asyncio.gather(*tasks)
        assert [result.totalResults for result in results] == [1, 1, 1]
        assert calls == 3
        assert all(stream.closed for stream in streams)
        assert client._concurrency._value == 2
        await client.aclose()

    asyncio.run(exercise())


@pytest.mark.unit
def test_retry_attempts_each_consume_request_budget() -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503)

    async def no_sleep(_: float) -> None:
        return None

    client = NVDClient(
        nvd_settings(NVD_MAX_RETRIES=1),
        transport=httpx.MockTransport(handler),
        sleep=no_sleep,
        budget=RequestBudget(1, 30),
    )
    with pytest.raises(NVDRateLimitError, match="local"):
        asyncio.run(client.fetch_cve("CVE-2021-44228"))
    asyncio.run(client.aclose())
    assert calls == 1


@pytest.mark.contract
def test_rich_fixture_normalizes_without_losing_cvss_cwe_or_cpe_logic() -> None:
    response = NVDResponse.model_validate(fixture_payload())
    record = normalize_nvd_response(response, "CVE-2021-44228", RETRIEVED_AT)

    assert record.cve_id == "CVE-2021-44228"
    assert record.publication_date == datetime(
        2021, 12, 10, 10, 15, tzinfo=timezone.utc
    )
    assert record.last_modified_date == datetime(
        2025, 10, 27, 8, 15, tzinfo=timezone.utc
    )
    assert record.preferred_description is not None
    assert record.preferred_description.language == "en"
    assert [metric.version.value for metric in record.cvss_metrics] == ["3.1", "2.0"]
    assert record.cvss_metrics[1].base_severity == "HIGH"
    assert record.weaknesses[0].identifier == "CWE-502"
    assert record.weaknesses[0].weakness_type == "Primary"
    configuration = record.affected_product_criteria[0]
    assert configuration.operator == "AND"
    assert [node.operator for node in configuration.nodes] == ["OR", "OR"]
    assert configuration.nodes[1].negate is True
    assert configuration.nodes[0].matches[0].version_end_excluding == "2.0"
    assert record.provenance.provider == "NVD"
    assert record.provenance.data_completeness.value == "complete"
    assert record.provenance.retrieved_at == RETRIEVED_AT
    assert record.provenance.provider_generated_at == datetime(
        2026, 10, 25, 12, 0, tzinfo=timezone.utc
    )
    assert not hasattr(record, "risk_score")


@pytest.mark.contract
def test_missing_fields_and_rejected_status_are_honest() -> None:
    response = NVDResponse.model_validate(
        fixture_payload("nvd_cve_rejected_synthetic.json")
    )
    record = normalize_nvd_response(response, "CVE-2020-1234", RETRIEVED_AT)

    assert record.vulnerability_status == "Rejected"
    assert record.cvss_metrics == ()
    assert record.weaknesses == ()
    assert record.affected_product_criteria == ()
    assert record.provenance.data_completeness.value == "rejected"
    assert {item.code for item in record.limitations} >= {
        "record_rejected",
        "metrics_unavailable",
        "weaknesses_unavailable",
        "affected_criteria_unavailable",
    }


@pytest.mark.contract
def test_unknown_status_and_empty_descriptions_are_preserved() -> None:
    payload = fixture_payload()
    cve = payload["vulnerabilities"][0]["cve"]
    cve["vulnStatus"] = "Future Provider Status"
    cve["descriptions"] = []
    record = normalize_nvd_response(
        NVDResponse.model_validate(payload), "CVE-2021-44228", RETRIEVED_AT
    )
    assert record.vulnerability_status == "Future Provider Status"
    assert record.descriptions == ()
    assert record.preferred_description is None
    assert "descriptions_unavailable" in {item.code for item in record.limitations}


@pytest.mark.contract
def test_provider_utc_timestamp_and_root_container_without_operator_are_supported() -> (
    None
):
    payload = fixture_payload()
    cve = payload["vulnerabilities"][0]["cve"]
    cve["published"] = "2021-12-10T10:15:09.143"
    configuration = cve["configurations"][0]
    configuration.pop("operator")
    configuration.pop("negate")

    record = normalize_nvd_response(
        NVDResponse.model_validate(payload), "CVE-2021-44228", RETRIEVED_AT
    )

    assert record.publication_date == datetime(
        2021, 12, 10, 10, 15, 9, 143000, tzinfo=timezone.utc
    )
    assert record.affected_product_criteria[0].operator is None
    assert record.affected_product_criteria[0].negate is None


@pytest.mark.contract
def test_all_cpe_bounds_multiple_roots_and_recursive_children_are_preserved() -> None:
    payload = fixture_payload()
    configurations = payload["vulnerabilities"][0]["cve"]["configurations"]
    first_node = configurations[0]["nodes"][0]
    first_node["cpeMatch"].append(
        {
            "vulnerable": False,
            "criteria": "cpe:2.3:a:example:second_product:*:*:*:*:*:*:*:*",
            "matchCriteriaId": "22222222-2222-4222-8222-222222222222",
            "versionStartExcluding": "2.0",
            "versionEndIncluding": "3.0",
        }
    )
    first_node["nodes"] = [
        {
            "operator": "AND",
            "negate": True,
            "cpeMatch": [
                {
                    "vulnerable": False,
                    "criteria": "cpe:2.3:h:example:device:*:*:*:*:*:*:*:*",
                }
            ],
        }
    ]
    configurations.append(
        {
            "operator": "OR",
            "negate": True,
            "cpeMatch": [
                {
                    "vulnerable": True,
                    "criteria": "cpe:2.3:o:example:other_os:*:*:*:*:*:*:*:*",
                }
            ],
            "nodes": [],
        }
    )

    record = normalize_nvd_response(
        NVDResponse.model_validate(payload), "CVE-2021-44228", RETRIEVED_AT
    )
    first_match, ranged_match = record.affected_product_criteria[0].nodes[0].matches
    child = record.affected_product_criteria[0].nodes[0].children[0]
    second_root = record.affected_product_criteria[1]

    assert first_match.version_start_including == "1.0"
    assert first_match.version_end_excluding == "2.0"
    assert first_match.match_criteria_id == "11111111-1111-4111-8111-111111111111"
    assert ranged_match.version_start_excluding == "2.0"
    assert ranged_match.version_end_including == "3.0"
    assert ranged_match.vulnerable is False
    assert child.operator == "AND"
    assert child.negate is True
    assert child.matches[0].vulnerable is False
    assert second_root.operator == "OR"
    assert second_root.negate is True
    assert second_root.matches[0].vulnerable is True


@pytest.mark.contract
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("format", "OTHER"),
        ("version", "3.0"),
        ("format", None),
        ("version", None),
    ],
)
def test_incompatible_or_missing_provider_contract_metadata_is_rejected(
    field: str, value: str | None
) -> None:
    payload = fixture_payload()
    if value is None:
        payload.pop(field)
    else:
        payload[field] = value
    client = make_client(
        lambda _: httpx.Response(
            200,
            json=payload,
            headers={"content-type": "application/json"},
        )
    )

    with pytest.raises(NVDInvalidResponseError, match="provider contract"):
        asyncio.run(client.fetch_cve("CVE-2021-44228"))
    asyncio.run(client.aclose())


@pytest.mark.contract
def test_invalid_provider_generation_timestamp_is_rejected() -> None:
    payload = fixture_payload()
    payload["timestamp"] = "not-a-timestamp"
    with pytest.raises(NVDInvalidResponseError, match="timestamp"):
        normalize_nvd_response(
            NVDResponse.model_validate(payload), "CVE-2021-44228", RETRIEVED_AT
        )


@pytest.mark.contract
@pytest.mark.parametrize("defect", ["id", "pagination", "cvss"])
def test_inconsistent_provider_records_are_rejected(defect: str) -> None:
    payload = fixture_payload()
    if defect == "id":
        payload["vulnerabilities"][0]["cve"]["id"] = "CVE-2022-0001"
    elif defect == "pagination":
        payload["totalResults"] = 2
    else:
        payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"][
            "version"
        ] = "3.0"
    with pytest.raises(NVDInvalidResponseError):
        normalize_nvd_response(
            NVDResponse.model_validate(payload), "CVE-2021-44228", RETRIEVED_AT
        )


@pytest.mark.contract
@pytest.mark.parametrize("defect", ["page_size", "invalid_id", "invalid_timestamp"])
def test_additional_provider_contract_inconsistencies_are_rejected(defect: str) -> None:
    payload = fixture_payload()
    if defect == "page_size":
        payload["resultsPerPage"] = 0
    elif defect == "invalid_id":
        payload["vulnerabilities"][0]["cve"]["id"] = "not-a-cve"
    else:
        payload["vulnerabilities"][0]["cve"]["published"] = "not-a-timestamp"
    with pytest.raises(NVDInvalidResponseError):
        normalize_nvd_response(
            NVDResponse.model_validate(payload), "CVE-2021-44228", RETRIEVED_AT
        )


@pytest.mark.unit
def test_public_contract_forbids_extra_fields_and_naive_timestamps() -> None:
    record = normalize_nvd_response(
        NVDResponse.model_validate(fixture_payload()),
        "CVE-2021-44228",
        RETRIEVED_AT,
    )
    payload = record.model_dump()
    payload["fabricated_score"] = 0
    with pytest.raises(ValidationError, match="extra_forbidden"):
        VulnerabilityRecord.model_validate(payload)
    payload.pop("fabricated_score")
    payload["publication_date"] = datetime(2021, 1, 1)
    with pytest.raises(ValidationError, match="timezone"):
        VulnerabilityRecord.model_validate(payload)


class StubNVDClient:
    def __init__(
        self,
        response: NVDResponse | None = None,
        error: Exception | None = None,
    ) -> None:
        self.response = response or NVDResponse.model_validate(fixture_payload())
        self.error = error
        self.closed = False

    async def fetch_cve(self, _: str) -> NVDResponse:
        if self.error is not None:
            raise self.error
        return self.response

    async def aclose(self) -> None:
        self.closed = True


def client_for(stub: StubNVDClient) -> TestClient:
    application = create_app(
        nvd_settings(),
        nvd_client_factory=lambda _: stub,  # type: ignore[arg-type,return-value]
    )
    return TestClient(application)


@pytest.mark.integration
def test_vulnerability_endpoint_returns_exact_typed_schema_and_closes_client() -> None:
    stub = StubNVDClient()
    with client_for(stub) as client:
        response = client.get("/api/v1/vulnerabilities/CVE-2021-44228")
        assert stub.closed is False
    assert stub.closed is True
    assert response.status_code == 200
    body = response.json()
    assert set(body) == set(VulnerabilityRecord.model_fields)
    assert body["cve_id"] == "CVE-2021-44228"
    assert body["source"] == "NVD"
    assert body["provenance"]["provider_api_version"] == "2.0"


@pytest.mark.integration
def test_fastapi_endpoint_runs_real_nvd_client_transport_and_normalizer() -> None:
    observed_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed_requests.append(request)
        return httpx.Response(
            200,
            json=fixture_payload(),
            headers={"content-type": "application/json"},
        )

    def factory(settings: Settings) -> NVDClient:
        return NVDClient(settings, transport=httpx.MockTransport(handler))

    application = create_app(nvd_settings(), nvd_client_factory=factory)
    with TestClient(application) as client:
        response = client.get("/api/v1/vulnerabilities/CVE-2021-44228")

    assert response.status_code == 200
    assert response.json()["cve_id"] == "CVE-2021-44228"
    assert response.json()["provenance"]["provider_generated_at"] == (
        "2026-10-25T12:00:00Z"
    )
    assert len(observed_requests) == 1
    assert observed_requests[0].url.params["cveId"] == "CVE-2021-44228"


@pytest.mark.integration
def test_fastapi_endpoint_maps_incompatible_nvd_metadata_to_502() -> None:
    payload = fixture_payload()
    payload["version"] = "3.0"

    def factory(settings: Settings) -> NVDClient:
        return NVDClient(
            settings,
            transport=httpx.MockTransport(
                lambda _: httpx.Response(
                    200,
                    json=payload,
                    headers={"content-type": "application/json"},
                )
            ),
        )

    application = create_app(nvd_settings(), nvd_client_factory=factory)
    with TestClient(application) as client:
        response = client.get("/api/v1/vulnerabilities/CVE-2021-44228")

    assert response.status_code == 502
    assert response.json() == {"detail": "NVD returned an invalid response."}


@pytest.mark.security
@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/vulnerabilities/cve-2021-44228",
        "/api/v1/vulnerabilities/CVE-2021-123",
        "/api/v1/vulnerabilities/https:%2F%2Fevil.test",
        "/api/v1/vulnerabilities/CVE-2021-44228%2F..%2Fhealth",
    ],
)
def test_endpoint_rejects_invalid_or_manipulated_paths(path: str) -> None:
    with client_for(StubNVDClient()) as client:
        response = client.get(path)
    assert response.status_code in {404, 422}


@pytest.mark.integration
@pytest.mark.parametrize(
    ("error", "status_code"),
    [
        (NVDNotFoundError("missing"), 404),
        (NVDRateLimitError("limited"), 429),
        (NVDInvalidResponseError("bad"), 502),
        (NVDUnavailableError("offline"), 503),
        (NVDTimeoutError("slow"), 504),
        (RuntimeError("private secret"), 500),
    ],
)
def test_endpoint_maps_provider_errors_without_leaking_details(
    error: Exception, status_code: int
) -> None:
    with client_for(StubNVDClient(error=error)) as client:
        response = client.get("/api/v1/vulnerabilities/CVE-2021-44228")
    assert response.status_code == status_code
    assert "private" not in response.text
    assert "secret" not in response.text


@pytest.mark.contract
def test_openapi_documents_vulnerability_contract_and_error_taxonomy() -> None:
    with client_for(StubNVDClient()) as client:
        schema = client.get("/openapi.json").json()
        assert client.get("/api/v1/health/").status_code == 200
    operation = schema["paths"]["/api/v1/vulnerabilities/{cve_id}"]["get"]
    assert operation["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/VulnerabilityRecord"
    }
    assert {"404", "422", "429", "500", "502", "503", "504"} <= set(
        operation["responses"]
    )
    serialized = json.dumps(operation)
    assert "requestBody" not in operation
    assert "url" not in [item["name"] for item in operation["parameters"]]
    assert "apiKey" not in serialized


@pytest.mark.unit
def test_optional_provider_fields_are_not_fabricated() -> None:
    payload = fixture_payload()
    cve = payload["vulnerabilities"][0]["cve"]
    for key in [
        "published",
        "lastModified",
        "sourceIdentifier",
        "vulnStatus",
        "descriptions",
        "metrics",
        "weaknesses",
        "configurations",
        "references",
    ]:
        cve.pop(key, None)
    record = normalize_nvd_response(
        NVDResponse.model_validate(payload), "CVE-2021-44228", RETRIEVED_AT
    )
    assert record.publication_date is None
    assert record.last_modified_date is None
    assert record.source_identifier is None
    assert record.vulnerability_status is None
    assert record.cvss_metrics == ()
    assert record.references == ()
    assert record.provenance.data_completeness.value == "minimal"


@pytest.mark.integration
def test_interpretation_endpoint_returns_typed_non_operational_result() -> None:
    with client_for(StubNVDClient()) as client:
        response = client.get("/api/v1/vulnerabilities/CVE-2021-44228/interpretation")
    assert response.status_code == 200
    body = response.json()
    assert body["cvss"]["selection_status"] == "selected"
    assert body["cvss"]["risk_score"] is None
    assert body["weaknesses"][0]["classification_status"] == "classified"
    assert body["weaknesses"][0]["weakness_type"] == "Primary"
    assert body["applicability"] is None


def declared_inventory() -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "inventory_id": "api-test",
        "products": [
            {
                "product_id": "application",
                "cpe23_name": ("cpe:2.3:a:example:synthetic_product:1.5:*:*:*:*:*:*:*"),
                "version": "1.5",
                "version_scheme": "numeric",
                "evidence_type": "declared",
            }
        ],
        "provenance": {"source": "integration-test", "collected_at": None},
        "completeness": "complete",
    }


@pytest.mark.integration
def test_applicability_endpoint_evaluates_intact_tree_and_does_not_persist() -> None:
    stub = StubNVDClient()
    with client_for(stub) as client:
        response = client.post(
            "/api/v1/vulnerabilities/CVE-2021-44228/applicability",
            json=declared_inventory(),
        )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "potentially_applicable"
    assert body["truth"] == "true"
    assert body["evaluation_tree"]["children"][0]["children"][1]["negated"] is True
    assert "confirmed_vulnerable" not in response.text


@pytest.mark.integration
def test_applicability_endpoint_rejects_invalid_and_oversized_inventory() -> None:
    invalid = declared_inventory()
    invalid["confirmed_vulnerable"] = True
    with client_for(StubNVDClient()) as client:
        response = client.post(
            "/api/v1/vulnerabilities/CVE-2021-44228/applicability", json=invalid
        )
    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid asset inventory."}

    application = create_app(
        nvd_settings(VULNERABILITY_MAX_INVENTORY_BODY_BYTES=1024),
        nvd_client_factory=lambda _: StubNVDClient(),  # type: ignore[arg-type,return-value]
    )
    with TestClient(application) as client:
        response = client.post(
            "/api/v1/vulnerabilities/CVE-2021-44228/applicability",
            content=b"{" + b" " * 1024 + b"}",
            headers={"content-type": "application/json"},
        )
    assert response.status_code == 413


@pytest.mark.contract
def test_openapi_documents_interpretation_and_bounded_inventory_body() -> None:
    with client_for(StubNVDClient()) as client:
        schema = client.get("/openapi.json").json()
    interpretation = schema["paths"]["/api/v1/vulnerabilities/{cve_id}/interpretation"][
        "get"
    ]
    applicability = schema["paths"]["/api/v1/vulnerabilities/{cve_id}/applicability"][
        "post"
    ]
    assert interpretation["responses"]["200"]["content"]["application/json"]
    assert applicability["requestBody"]["required"] is True
    assert "AssetInventory" in json.dumps(applicability["requestBody"])
    assert "413" in applicability["responses"]
