from __future__ import annotations

import asyncio
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, datetime, timezone
from time import monotonic
from typing import Protocol

from app.core.config import Settings
from app.integrations.first_epss.client import EPSS_ENDPOINT, EPSSInvalidResponseError
from app.integrations.first_epss.schemas import FIRSTEPSSResponse
from app.schemas.epss import (
    EPSSFreshness,
    EPSSLookupResult,
    EPSSLookupStatus,
    EPSSProvenance,
)
from app.schemas.vulnerability import normalize_cve_id

_LIMITATIONS = (
    "EPSS estimates exploitation probability in the next 30 days; it is not proof "
    "of exploitation or a severity score.",
    "Percentile is the share of scored vulnerabilities at or below this score.",
    "Use EPSS with asset context, exposure, impact, and other threat intelligence.",
)


@dataclass(frozen=True)
class _CacheEntry:
    result: EPSSLookupResult
    expires_at: float


@dataclass
class _InFlightOperation:
    task: asyncio.Task[EPSSLookupResult]
    active_waiters: int
    cancellation_requested: bool = False


class EPSSProviderClient(Protocol):
    async def fetch_cve(self, cve_id: str) -> FIRSTEPSSResponse: ...


class EPSSIntelligenceService:
    """Normalizes point lookups and provides a bounded, process-local cache."""

    def __init__(
        self,
        settings: Settings,
        client: EPSSProviderClient,
        *,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        clock: Callable[[], float] = monotonic,
    ) -> None:
        self._client = client
        self._now = now
        self._clock = clock
        self._ttl = settings.EPSS_CACHE_TTL_SECONDS
        self._maximum_entries = settings.EPSS_CACHE_MAX_ENTRIES
        self._current_days = settings.EPSS_CURRENT_MAX_AGE_DAYS
        self._stale_days = settings.EPSS_STALE_MAX_AGE_DAYS
        self._cache: OrderedDict[str, _CacheEntry] = OrderedDict()
        self._inflight: dict[str, _InFlightOperation] = {}
        self._lock = asyncio.Lock()
        self._closed = False

    async def lookup(self, cve_id: str) -> EPSSLookupResult:
        normalized = normalize_cve_id(cve_id)
        async with self._lock:
            if self._closed:
                raise RuntimeError("EPSS intelligence service is closed")
            cached = self._cache.get(normalized)
            if cached is not None and cached.expires_at > self._clock():
                self._cache.move_to_end(normalized)
                return self._with_current_freshness(cached.result)
            if cached is not None:
                del self._cache[normalized]
            operation = self._inflight.get(normalized)
            if operation is None:
                task = asyncio.create_task(self._fetch_and_cache(normalized))
                operation = _InFlightOperation(task=task, active_waiters=0)
                self._inflight[normalized] = operation
            operation.active_waiters += 1
        try:
            return await asyncio.shield(operation.task)
        finally:
            await self._release_waiter(normalized, operation)

    async def aclose(self) -> None:
        async with self._lock:
            self._closed = True
            operations = tuple(self._inflight.values())
            self._inflight.clear()
            for operation in operations:
                operation.cancellation_requested = True
                operation.task.cancel()
        if operations:
            await asyncio.gather(
                *(operation.task for operation in operations),
                return_exceptions=True,
            )

    async def _release_waiter(self, cve_id: str, operation: _InFlightOperation) -> None:
        task_to_collect: asyncio.Task[EPSSLookupResult] | None = None
        async with self._lock:
            if operation.active_waiters <= 0:
                raise RuntimeError("EPSS waiter release is unbalanced")
            operation.active_waiters -= 1
            if operation.active_waiters == 0:
                if not operation.task.done():
                    operation.cancellation_requested = True
                    operation.task.cancel()
                if self._inflight.get(cve_id) is operation:
                    del self._inflight[cve_id]
                task_to_collect = operation.task
        if task_to_collect is not None:
            await asyncio.gather(task_to_collect, return_exceptions=True)

    async def _fetch_and_cache(self, cve_id: str) -> EPSSLookupResult:
        try:
            provider = await self._client.fetch_cve(cve_id)
            result = self._normalize(cve_id, provider)
            await self._commit_if_authorized(cve_id, result)
            return result
        finally:
            async with self._lock:
                operation = self._inflight.get(cve_id)
                if operation is not None and operation.task is asyncio.current_task():
                    del self._inflight[cve_id]

    async def _commit_if_authorized(
        self, cve_id: str, result: EPSSLookupResult
    ) -> bool:
        task = asyncio.current_task()
        async with self._lock:
            operation = self._inflight.get(cve_id)
            if (
                self._closed
                or operation is None
                or operation.task is not task
                or operation.cancellation_requested
            ):
                return False
            self._cache[cve_id] = _CacheEntry(
                result=result,
                expires_at=self._clock() + self._ttl,
            )
            self._cache.move_to_end(cve_id)
            while len(self._cache) > self._maximum_entries:
                self._cache.popitem(last=False)
            return True

    def _normalize(self, cve_id: str, response: FIRSTEPSSResponse) -> EPSSLookupResult:
        retrieved_at = self._normalized_now()
        if response.total == 0:
            return EPSSLookupResult(
                cve_id=cve_id,
                status=EPSSLookupStatus.NOT_SCORED,
                score=None,
                percentile=None,
                score_date=None,
                freshness=EPSSFreshness.UNAVAILABLE,
                provenance=EPSSProvenance(
                    api_version=response.version,
                    source_url=EPSS_ENDPOINT,
                    retrieved_at=retrieved_at,
                    source_score_date=None,
                    model_version=None,
                ),
                limitations=_LIMITATIONS,
            )
        if response.total != 1 or len(response.data) != 1:
            raise EPSSInvalidResponseError(
                "FIRST EPSS returned an invalid point lookup count"
            )
        datum = response.data[0]
        if datum.cve != cve_id:
            raise EPSSInvalidResponseError(
                "FIRST EPSS returned a different CVE identifier"
            )
        freshness = self._freshness(datum.date, retrieved_at.date())
        return EPSSLookupResult(
            cve_id=cve_id,
            status=EPSSLookupStatus.AVAILABLE,
            score=datum.epss,
            percentile=datum.percentile,
            score_date=datum.date,
            freshness=freshness,
            provenance=EPSSProvenance(
                api_version=response.version,
                source_url=EPSS_ENDPOINT,
                retrieved_at=retrieved_at,
                source_score_date=datum.date,
                model_version=None,
            ),
            limitations=_LIMITATIONS,
        )

    def _with_current_freshness(self, result: EPSSLookupResult) -> EPSSLookupResult:
        if result.score_date is None:
            return result
        freshness = self._freshness(result.score_date, self._normalized_now().date())
        return result.model_copy(update={"freshness": freshness})

    def _freshness(self, score_date: date, today: date) -> EPSSFreshness:
        age = (today - score_date).days
        if age < 0:
            raise EPSSInvalidResponseError("FIRST EPSS returned a future score date")
        if age <= self._current_days:
            return EPSSFreshness.CURRENT
        if age <= self._stale_days:
            return EPSSFreshness.STALE
        return EPSSFreshness.HISTORICAL

    def _normalized_now(self) -> datetime:
        value = self._now()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("EPSS service clock must be timezone-aware")
        return value.astimezone(timezone.utc)
