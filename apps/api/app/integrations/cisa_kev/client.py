from __future__ import annotations

import asyncio
import hashlib
import json
import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Final
from urllib.parse import urlsplit

import httpx
from pydantic import ValidationError

from app.core.config import Settings
from app.integrations.cisa_kev.schemas import CISAKEVCatalog

KEV_CATALOG_ENDPOINT: Final = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
_CHUNK_SIZE: Final = 64 * 1024
_MAX_JSON_DEPTH: Final = 16


class KEVClientError(RuntimeError):
    """Base class for sanitized CISA provider failures."""


class KEVTimeoutError(KEVClientError):
    pass


class KEVRateLimitError(KEVClientError):
    pass


class KEVUnavailableError(KEVClientError):
    pass


class KEVInvalidResponseError(KEVClientError):
    pass


class KEVResponseTooLargeError(KEVInvalidResponseError):
    pass


@dataclass(frozen=True)
class FetchedKEVCatalog:
    catalog: CISAKEVCatalog
    content_digest: str
    decoded_bytes: int


def validate_kev_endpoint(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "www.cisa.gov"
        or parsed.port not in {None, 443}
        or parsed.path
        != "/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise ValueError("KEV endpoint is not the approved HTTPS endpoint")
    return value


def _validate_json_depth(value: object) -> None:
    pending: list[tuple[object, int]] = [(value, 1)]
    while pending:
        current, depth = pending.pop()
        if depth > _MAX_JSON_DEPTH:
            raise KEVInvalidResponseError("CISA KEV JSON exceeded the depth limit")
        if isinstance(current, dict):
            pending.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            pending.extend((item, depth + 1) for item in current)


Sleep = Callable[[float], Awaitable[None]]


class KEVClient:
    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Sleep = asyncio.sleep,
        random_source: Callable[[], float] = random.random,
    ) -> None:
        self._endpoint = validate_kev_endpoint(KEV_CATALOG_ENDPOINT)
        self._maximum_response_bytes = settings.KEV_MAX_RESPONSE_BYTES
        self._maximum_entries = settings.KEV_MAX_ENTRIES
        self._total_deadline_seconds = settings.KEV_TOTAL_DEADLINE_SECONDS
        self._maximum_retries = settings.KEV_MAX_RETRIES
        self._backoff_seconds = settings.KEV_BACKOFF_SECONDS
        self._maximum_retry_after_seconds = settings.KEV_MAX_RETRY_AFTER_SECONDS
        self._sleep = sleep
        self._random = random_source
        self._concurrency = asyncio.Semaphore(settings.KEV_MAX_CONCURRENCY)
        timeout = httpx.Timeout(settings.KEV_TIMEOUT_SECONDS)
        limits = httpx.Limits(
            max_connections=settings.KEV_MAX_CONCURRENCY,
            max_keepalive_connections=settings.KEV_MAX_CONCURRENCY,
        )
        self._http = httpx.AsyncClient(
            headers={
                "Accept": "application/json",
                "User-Agent": f"iCYLENS/{settings.APP_VERSION} CISA-KEV-client",
            },
            timeout=timeout,
            limits=limits,
            verify=True,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def fetch_catalog(self) -> FetchedKEVCatalog:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._total_deadline_seconds
        try:
            async with asyncio.timeout(self._total_deadline_seconds):
                async with self._concurrency:
                    response = await self._request_with_retries()
                    body = await self._read_bounded(response)
                self._ensure_deadline(deadline)
                try:
                    payload = json.loads(body)
                except (json.JSONDecodeError, UnicodeDecodeError) as error:
                    raise KEVInvalidResponseError(
                        "CISA KEV returned invalid JSON"
                    ) from error
                _validate_json_depth(payload)
                if not isinstance(payload, dict):
                    raise KEVInvalidResponseError("CISA KEV envelope was invalid")
                entries = payload.get("vulnerabilities")
                if not isinstance(entries, list):
                    raise KEVInvalidResponseError("CISA KEV entries were invalid")
                if len(entries) > self._maximum_entries:
                    raise KEVInvalidResponseError(
                        "CISA KEV catalog exceeded the entry limit"
                    )
                self._ensure_deadline(deadline)
                try:
                    catalog = CISAKEVCatalog.model_validate(payload)
                except ValidationError as error:
                    raise KEVInvalidResponseError(
                        "CISA KEV response did not match the provider contract"
                    ) from error
                self._ensure_deadline(deadline)
                return FetchedKEVCatalog(
                    catalog=catalog,
                    content_digest=hashlib.sha256(body).hexdigest(),
                    decoded_bytes=len(body),
                )
        except TimeoutError as error:
            raise KEVTimeoutError(
                "CISA KEV operation exceeded its total deadline"
            ) from error

    async def _request_with_retries(self) -> httpx.Response:
        for attempt in range(self._maximum_retries + 1):
            try:
                request = self._http.build_request("GET", self._endpoint)
                response = await self._http.send(request, stream=True)
            except httpx.TimeoutException as error:
                if attempt >= self._maximum_retries:
                    raise KEVTimeoutError("CISA KEV request timed out") from error
                await self._sleep(self._retry_delay(attempt, None))
                continue
            except httpx.TransportError as error:
                if attempt >= self._maximum_retries:
                    raise KEVUnavailableError("CISA KEV transport failed") from error
                await self._sleep(self._retry_delay(attempt, None))
                continue

            if response.status_code in {301, 302, 303, 307, 308}:
                await response.aclose()
                raise KEVInvalidResponseError(
                    "CISA KEV returned an unexpected redirect"
                )
            if response.status_code == 403:
                await response.aclose()
                raise KEVUnavailableError("CISA KEV denied the request")
            if response.status_code == 429 or 500 <= response.status_code <= 599:
                if attempt >= self._maximum_retries:
                    await response.aclose()
                    if response.status_code == 429:
                        raise KEVRateLimitError("CISA KEV rate limit was reached")
                    raise KEVUnavailableError("CISA KEV is temporarily unavailable")
                retry_after = response.headers.get("retry-after")
                await response.aclose()
                await self._sleep(self._retry_delay(attempt, retry_after))
                continue
            if response.is_error:
                await response.aclose()
                raise KEVInvalidResponseError(
                    "CISA KEV returned an unexpected HTTP status"
                )
            return response
        raise AssertionError("bounded retry loop exhausted unexpectedly")

    async def _read_bounded(self, response: httpx.Response) -> bytearray:
        content = bytearray()
        try:
            content_type = response.headers.get("content-type", "")
            if content_type.split(";", 1)[0].strip().lower() != "application/json":
                raise KEVInvalidResponseError(
                    "CISA KEV returned an unexpected content type"
                )
            declared_length = response.headers.get("content-length")
            if declared_length is not None:
                try:
                    parsed_length = int(declared_length)
                except ValueError as error:
                    raise KEVInvalidResponseError(
                        "CISA KEV returned invalid Content-Length"
                    ) from error
                if parsed_length < 0:
                    raise KEVInvalidResponseError(
                        "CISA KEV returned invalid Content-Length"
                    )
                if parsed_length > self._maximum_response_bytes:
                    raise KEVResponseTooLargeError(
                        "CISA KEV response exceeded the byte limit"
                    )
            chunk_size = min(_CHUNK_SIZE, self._maximum_response_bytes + 1)
            async for chunk in response.aiter_bytes(chunk_size):
                content.extend(chunk)
                if len(content) > self._maximum_response_bytes:
                    raise KEVResponseTooLargeError(
                        "CISA KEV response exceeded the byte limit"
                    )
        except httpx.DecodingError as error:
            raise KEVInvalidResponseError(
                "CISA KEV response content encoding was invalid"
            ) from error
        except httpx.TimeoutException as error:
            raise KEVTimeoutError("CISA KEV response body timed out") from error
        except httpx.TransportError as error:
            raise KEVUnavailableError(
                "CISA KEV response body was interrupted"
            ) from error
        finally:
            await response.aclose()
        return content

    def _ensure_deadline(self, deadline: float) -> None:
        if asyncio.get_running_loop().time() >= deadline:
            raise KEVTimeoutError("CISA KEV operation exceeded its total deadline")

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
