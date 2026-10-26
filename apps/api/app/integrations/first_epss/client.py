from __future__ import annotations

import asyncio
import json
import random
from collections import deque
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from time import monotonic
from typing import Final
from urllib.parse import urlsplit

import httpx
from pydantic import ValidationError

from app.core.config import Settings
from app.integrations.first_epss.schemas import FIRSTEPSSResponse
from app.schemas.vulnerability import normalize_cve_id

EPSS_ENDPOINT: Final = "https://api.first.org/data/v1/epss"
_CHUNK_SIZE: Final = 64 * 1024


class EPSSClientError(RuntimeError):
    """Base class for sanitized FIRST provider failures."""


class EPSSTimeoutError(EPSSClientError):
    pass


class EPSSRateLimitError(EPSSClientError):
    pass


class EPSSUnavailableError(EPSSClientError):
    pass


class EPSSInvalidResponseError(EPSSClientError):
    pass


class EPSSResponseTooLargeError(EPSSInvalidResponseError):
    pass


def validate_epss_endpoint(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "api.first.org"
        or parsed.port not in {None, 443}
        or parsed.path != "/data/v1/epss"
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise ValueError("EPSS endpoint is not the approved HTTPS endpoint")
    return value


class RequestBudget:
    """Per-process rolling-window request budget with immediate rejection."""

    def __init__(
        self,
        maximum_requests: int,
        window_seconds: float,
        *,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        self._maximum_requests = maximum_requests
        self._window_seconds = window_seconds
        self._clock = clock
        self._requests: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def try_acquire(self) -> bool:
        async with self._lock:
            now = self._clock()
            threshold = now - self._window_seconds
            while self._requests and self._requests[0] <= threshold:
                self._requests.popleft()
            if len(self._requests) >= self._maximum_requests:
                return False
            self._requests.append(now)
            return True


Sleep = Callable[[float], Awaitable[None]]


class EPSSClient:
    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Sleep = asyncio.sleep,
        random_source: Callable[[], float] = random.random,
        budget: RequestBudget | None = None,
    ) -> None:
        self._endpoint = validate_epss_endpoint(EPSS_ENDPOINT)
        self._maximum_response_bytes = settings.EPSS_MAX_RESPONSE_BYTES
        self._total_deadline_seconds = settings.EPSS_TOTAL_DEADLINE_SECONDS
        self._maximum_retries = settings.EPSS_MAX_RETRIES
        self._backoff_seconds = settings.EPSS_BACKOFF_SECONDS
        self._maximum_retry_after_seconds = settings.EPSS_MAX_RETRY_AFTER_SECONDS
        self._sleep = sleep
        self._random = random_source
        self._budget = budget or RequestBudget(
            settings.EPSS_REQUESTS_PER_WINDOW,
            settings.EPSS_RATE_WINDOW_SECONDS,
        )
        self._concurrency = asyncio.Semaphore(settings.EPSS_MAX_CONCURRENCY)
        self._http = httpx.AsyncClient(
            headers={
                "Accept": "application/json",
                "User-Agent": f"iCYLENS/{settings.APP_VERSION} FIRST-EPSS-client",
            },
            timeout=httpx.Timeout(settings.EPSS_TIMEOUT_SECONDS),
            limits=httpx.Limits(
                max_connections=settings.EPSS_MAX_CONCURRENCY,
                max_keepalive_connections=settings.EPSS_MAX_CONCURRENCY,
            ),
            verify=True,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def fetch_cve(self, cve_id: str) -> FIRSTEPSSResponse:
        validated_id = normalize_cve_id(cve_id)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._total_deadline_seconds
        try:
            async with asyncio.timeout(self._total_deadline_seconds):
                async with self._concurrency:
                    response = await self._request_with_retries(validated_id)
                    body = await self._read_bounded(response)
                self._ensure_deadline(deadline)
                try:
                    payload = json.loads(body)
                except (json.JSONDecodeError, UnicodeDecodeError) as error:
                    raise EPSSInvalidResponseError(
                        "FIRST EPSS returned invalid JSON"
                    ) from error
                self._ensure_deadline(deadline)
                try:
                    result = FIRSTEPSSResponse.model_validate(payload)
                    result.ensure_point_query()
                except (ValidationError, ValueError) as error:
                    raise EPSSInvalidResponseError(
                        "FIRST EPSS response did not match the provider contract"
                    ) from error
                self._ensure_deadline(deadline)
                return result
        except TimeoutError as error:
            raise EPSSTimeoutError(
                "FIRST EPSS operation exceeded its total deadline"
            ) from error

    async def _request_with_retries(self, cve_id: str) -> httpx.Response:
        for attempt in range(self._maximum_retries + 1):
            if not await self._budget.try_acquire():
                raise EPSSRateLimitError("local EPSS request budget is exhausted")
            try:
                request = self._http.build_request(
                    "GET", self._endpoint, params={"cve": cve_id}
                )
                response = await self._http.send(request, stream=True)
            except httpx.TimeoutException as error:
                if attempt >= self._maximum_retries:
                    raise EPSSTimeoutError("FIRST EPSS request timed out") from error
                await self._sleep(self._retry_delay(attempt, None))
                continue
            except httpx.TransportError as error:
                if attempt >= self._maximum_retries:
                    raise EPSSUnavailableError("FIRST EPSS transport failed") from error
                await self._sleep(self._retry_delay(attempt, None))
                continue

            if response.status_code in {301, 302, 303, 307, 308}:
                await response.aclose()
                raise EPSSInvalidResponseError(
                    "FIRST EPSS returned an unexpected redirect"
                )
            if response.status_code == 403:
                await response.aclose()
                raise EPSSUnavailableError("FIRST EPSS denied the request")
            if response.status_code == 429 or 500 <= response.status_code <= 599:
                if attempt >= self._maximum_retries:
                    await response.aclose()
                    if response.status_code == 429:
                        raise EPSSRateLimitError("FIRST EPSS rate limit was reached")
                    raise EPSSUnavailableError("FIRST EPSS is temporarily unavailable")
                retry_after = response.headers.get("retry-after")
                await response.aclose()
                await self._sleep(self._retry_delay(attempt, retry_after))
                continue
            if response.is_error:
                await response.aclose()
                raise EPSSInvalidResponseError(
                    "FIRST EPSS returned an unexpected HTTP status"
                )
            return response
        raise AssertionError("bounded retry loop exhausted unexpectedly")

    async def _read_bounded(self, response: httpx.Response) -> bytearray:
        content = bytearray()
        try:
            content_type = response.headers.get("content-type", "")
            if content_type.split(";", 1)[0].strip().lower() != "application/json":
                raise EPSSInvalidResponseError(
                    "FIRST EPSS returned an unexpected content type"
                )
            declared_length = response.headers.get("content-length")
            if declared_length is not None:
                try:
                    parsed_length = int(declared_length)
                except ValueError as error:
                    raise EPSSInvalidResponseError(
                        "FIRST EPSS returned invalid Content-Length"
                    ) from error
                if parsed_length < 0:
                    raise EPSSInvalidResponseError(
                        "FIRST EPSS returned invalid Content-Length"
                    )
                if parsed_length > self._maximum_response_bytes:
                    raise EPSSResponseTooLargeError(
                        "FIRST EPSS response exceeded the byte limit"
                    )
            chunk_size = min(_CHUNK_SIZE, self._maximum_response_bytes + 1)
            async for chunk in response.aiter_bytes(chunk_size):
                content.extend(chunk)
                if len(content) > self._maximum_response_bytes:
                    raise EPSSResponseTooLargeError(
                        "FIRST EPSS response exceeded the byte limit"
                    )
        except httpx.DecodingError as error:
            raise EPSSInvalidResponseError(
                "FIRST EPSS response content encoding was invalid"
            ) from error
        except httpx.TimeoutException as error:
            raise EPSSTimeoutError("FIRST EPSS response body timed out") from error
        except httpx.TransportError as error:
            raise EPSSUnavailableError(
                "FIRST EPSS response body was interrupted"
            ) from error
        finally:
            await response.aclose()
        return content

    def _ensure_deadline(self, deadline: float) -> None:
        if asyncio.get_running_loop().time() >= deadline:
            raise EPSSTimeoutError("FIRST EPSS operation exceeded its total deadline")

    def _retry_delay(self, attempt: int, retry_after: str | None) -> float:
        server_delay = self._parse_retry_after(retry_after)
        if server_delay is not None:
            return float(min(server_delay, self._maximum_retry_after_seconds))
        exponential = self._backoff_seconds * (2**attempt)
        jitter = self._backoff_seconds * self._random()
        return float(min(exponential + jitter, self._maximum_retry_after_seconds))

    def _parse_retry_after(self, value: str | None) -> float | None:
        if value is None:
            return None
        try:
            return max(0.0, float(value))
        except ValueError:
            try:
                target = parsedate_to_datetime(value)
            except (TypeError, ValueError, OverflowError):
                return None
            if target.tzinfo is None:
                target = target.replace(tzinfo=timezone.utc)
            return max(0.0, (target - datetime.now(timezone.utc)).total_seconds())
