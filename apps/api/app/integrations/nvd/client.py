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
from app.integrations.nvd.schemas import NVDResponse
from app.schemas.vulnerability import normalize_cve_id

NVD_CVE_ENDPOINT: Final = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CHUNK_SIZE: Final = 64 * 1024


class NVDClientError(RuntimeError):
    """Base class for sanitized provider failures."""


class NVDNotFoundError(NVDClientError):
    pass


class NVDTimeoutError(NVDClientError):
    pass


class NVDRateLimitError(NVDClientError):
    pass


class NVDUnavailableError(NVDClientError):
    pass


class NVDInvalidResponseError(NVDClientError):
    pass


class NVDResponseTooLargeError(NVDInvalidResponseError):
    pass


def validate_nvd_endpoint(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "services.nvd.nist.gov"
        or parsed.port not in {None, 443}
        or parsed.path != "/rest/json/cves/2.0"
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise ValueError("NVD endpoint is not the approved HTTPS endpoint")
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


class NVDClient:
    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Sleep = asyncio.sleep,
        random_source: Callable[[], float] = random.random,
        budget: RequestBudget | None = None,
    ) -> None:
        self._endpoint = validate_nvd_endpoint(NVD_CVE_ENDPOINT)
        self._maximum_response_bytes = settings.NVD_MAX_RESPONSE_BYTES
        self._total_deadline_seconds = settings.NVD_TOTAL_DEADLINE_SECONDS
        self._maximum_retries = settings.NVD_MAX_RETRIES
        self._backoff_seconds = settings.NVD_BACKOFF_SECONDS
        self._maximum_retry_after_seconds = settings.NVD_MAX_RETRY_AFTER_SECONDS
        self._sleep = sleep
        self._random = random_source
        self._budget = budget or RequestBudget(
            settings.NVD_REQUESTS_PER_WINDOW,
            settings.NVD_RATE_WINDOW_SECONDS,
        )
        self._concurrency = asyncio.Semaphore(settings.NVD_MAX_CONCURRENCY)
        headers = {
            "Accept": "application/json",
            "User-Agent": f"iCYLENS/{settings.APP_VERSION} NVD-client",
        }
        if settings.NVD_API_KEY is not None:
            headers["apiKey"] = settings.NVD_API_KEY.get_secret_value()
        timeout = httpx.Timeout(settings.NVD_TIMEOUT_SECONDS)
        limits = httpx.Limits(
            max_connections=settings.NVD_MAX_CONCURRENCY,
            max_keepalive_connections=settings.NVD_MAX_CONCURRENCY,
        )
        self._http = httpx.AsyncClient(
            headers=headers,
            timeout=timeout,
            limits=limits,
            verify=True,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def fetch_cve(self, cve_id: str) -> NVDResponse:
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
                    raise NVDInvalidResponseError(
                        "NVD returned invalid JSON"
                    ) from error
                self._ensure_deadline(deadline)
                try:
                    result = NVDResponse.model_validate(payload)
                except ValidationError as error:
                    raise NVDInvalidResponseError(
                        "NVD response did not match the provider contract"
                    ) from error
                self._ensure_deadline(deadline)
                return result
        except TimeoutError as error:
            raise NVDTimeoutError(
                "NVD operation exceeded its total deadline"
            ) from error

    async def _request_with_retries(self, cve_id: str) -> httpx.Response:
        for attempt in range(self._maximum_retries + 1):
            if not await self._budget.try_acquire():
                raise NVDRateLimitError("local NVD request budget is exhausted")
            try:
                request = self._http.build_request(
                    "GET", self._endpoint, params={"cveId": cve_id}
                )
                response = await self._http.send(request, stream=True)
            except httpx.TimeoutException as error:
                if attempt >= self._maximum_retries:
                    raise NVDTimeoutError("NVD request timed out") from error
                await self._sleep(self._retry_delay(attempt, None))
                continue
            except httpx.TransportError as error:
                if attempt >= self._maximum_retries:
                    raise NVDUnavailableError("NVD transport failed") from error
                await self._sleep(self._retry_delay(attempt, None))
                continue

            if response.status_code == 404:
                await response.aclose()
                raise NVDNotFoundError("CVE was not found by NVD")
            if response.status_code in {301, 302, 303, 307, 308}:
                await response.aclose()
                raise NVDInvalidResponseError("NVD returned an unexpected redirect")
            if response.status_code == 403:
                await response.aclose()
                raise NVDUnavailableError("NVD denied the request")
            if response.status_code == 429 or 500 <= response.status_code <= 599:
                if attempt >= self._maximum_retries:
                    await response.aclose()
                    if response.status_code == 429:
                        raise NVDRateLimitError("NVD rate limit was reached")
                    raise NVDUnavailableError("NVD is temporarily unavailable")
                retry_after = response.headers.get("retry-after")
                await response.aclose()
                await self._sleep(self._retry_delay(attempt, retry_after))
                continue
            if response.is_error:
                await response.aclose()
                raise NVDInvalidResponseError("NVD returned an unexpected HTTP status")
            return response
        raise AssertionError("bounded retry loop exhausted unexpectedly")

    async def _read_bounded(self, response: httpx.Response) -> bytearray:
        content = bytearray()
        try:
            content_type = response.headers.get("content-type", "")
            if content_type.split(";", 1)[0].strip().lower() != "application/json":
                raise NVDInvalidResponseError("NVD returned an unexpected content type")
            declared_length = response.headers.get("content-length")
            if declared_length is not None:
                try:
                    parsed_length = int(declared_length)
                except ValueError as error:
                    raise NVDInvalidResponseError(
                        "NVD returned invalid Content-Length"
                    ) from error
                if parsed_length < 0:
                    raise NVDInvalidResponseError("NVD returned invalid Content-Length")
                if parsed_length > self._maximum_response_bytes:
                    raise NVDResponseTooLargeError(
                        "NVD response exceeded the byte limit"
                    )

            chunk_size = min(_CHUNK_SIZE, self._maximum_response_bytes + 1)
            async for chunk in response.aiter_bytes(chunk_size):
                content.extend(chunk)
                if len(content) > self._maximum_response_bytes:
                    raise NVDResponseTooLargeError(
                        "NVD response exceeded the byte limit"
                    )
        except httpx.DecodingError as error:
            raise NVDInvalidResponseError(
                "NVD response content encoding was invalid"
            ) from error
        except httpx.TimeoutException as error:
            raise NVDTimeoutError("NVD response body timed out") from error
        except httpx.TransportError as error:
            raise NVDUnavailableError("NVD response body was interrupted") from error
        finally:
            await response.aclose()
        return content

    def _ensure_deadline(self, deadline: float) -> None:
        if asyncio.get_running_loop().time() >= deadline:
            raise NVDTimeoutError("NVD operation exceeded its total deadline")

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
