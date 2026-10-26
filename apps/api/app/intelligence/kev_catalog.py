from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Protocol

from app.core.config import Settings
from app.integrations.cisa_kev.client import (
    KEV_CATALOG_ENDPOINT,
    FetchedKEVCatalog,
)
from app.integrations.cisa_kev.schemas import CISAKEVEntry
from app.schemas.kev import (
    KEVCatalogStatus,
    KEVFreshnessStatus,
    KEVLookupResult,
    KEVPresenceStatus,
    KEVProvenance,
    KEVRecord,
    validate_kev_cve_id,
)


class KEVCatalogValidationError(RuntimeError):
    """A complete candidate catalog failed integrity validation."""


class KEVCatalogUnavailableError(RuntimeError):
    """No fully validated snapshot is available for lookup."""


class KEVCatalogFetcher(Protocol):
    async def fetch_catalog(self) -> FetchedKEVCatalog: ...


@dataclass(frozen=True)
class KEVCatalogSnapshot:
    catalog_version: str
    date_released: datetime
    fetched_at: datetime
    record_count: int
    source_url: str
    content_digest: str
    records_by_cve: Mapping[str, KEVRecord]
    validation_status: str = "validated"


def _normalize_record(
    entry: CISAKEVEntry, catalog_version: str, date_released: datetime
) -> KEVRecord:
    return KEVRecord(
        cve_id=entry.cveID,
        vendor_project=entry.vendorProject,
        product=entry.product,
        vulnerability_name=entry.vulnerabilityName,
        date_added=entry.dateAdded,
        short_description=entry.shortDescription,
        required_action=entry.requiredAction,
        due_date=entry.dueDate,
        known_ransomware_campaign_use=entry.knownRansomwareCampaignUse,
        forensic_triage=entry.forensicTriage,
        notes=entry.notes,
        cwes=entry.cwes,
        provenance=KEVProvenance(
            source_url=KEV_CATALOG_ENDPOINT,
            catalog_version=catalog_version,
            catalog_date_released=date_released,
        ),
    )


def build_snapshot(
    fetched: FetchedKEVCatalog,
    fetched_at: datetime,
    maximum_entries: int,
) -> KEVCatalogSnapshot:
    if fetched_at.tzinfo is None or fetched_at.utcoffset() is None:
        raise KEVCatalogValidationError("Snapshot retrieval time lacks a timezone")
    fetched_at = fetched_at.astimezone(timezone.utc)
    catalog = fetched.catalog
    released = catalog.dateReleased
    if released.tzinfo is None or released.utcoffset() is None:
        raise KEVCatalogValidationError("Catalog release time lacks a timezone")
    released = released.astimezone(timezone.utc)
    if catalog.count != len(catalog.vulnerabilities):
        raise KEVCatalogValidationError("Catalog count does not match its entries")
    if catalog.count > maximum_entries:
        raise KEVCatalogValidationError("Catalog exceeds the entry limit")
    if released > fetched_at:
        raise KEVCatalogValidationError("Catalog release time is in the future")

    records: dict[str, KEVRecord] = {}
    for entry in catalog.vulnerabilities:
        if entry.cveID in records:
            raise KEVCatalogValidationError("Catalog contains a duplicate CVE")
        if entry.dueDate < entry.dateAdded:
            raise KEVCatalogValidationError("Catalog contains contradictory dates")
        records[entry.cveID] = _normalize_record(
            entry, catalog.catalogVersion, released
        )
    return KEVCatalogSnapshot(
        catalog_version=catalog.catalogVersion,
        date_released=released,
        fetched_at=fetched_at,
        record_count=len(records),
        source_url=KEV_CATALOG_ENDPOINT,
        content_digest=fetched.content_digest,
        records_by_cve=MappingProxyType(records),
    )


class KEVCatalogStore:
    def __init__(
        self,
        settings: Settings,
        *,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._maximum_entries = settings.KEV_MAX_ENTRIES
        self._freshness_seconds = settings.KEV_FRESHNESS_SECONDS
        self._now = now
        self._snapshot: KEVCatalogSnapshot | None = None
        self._refresh_attempted = False
        self._refresh_lock = asyncio.Lock()
        self._refresh_task: asyncio.Task[KEVCatalogSnapshot] | None = None
        self._closed = False

    @property
    def snapshot(self) -> KEVCatalogSnapshot | None:
        return self._snapshot

    async def refresh(self, client: KEVCatalogFetcher) -> KEVCatalogSnapshot:
        async with self._refresh_lock:
            if self._closed:
                raise RuntimeError("KEV catalog store is closed")
            task = self._refresh_task
            if task is None:
                self._refresh_attempted = True
                task = asyncio.create_task(self._fetch_validate_promote(client))
                task.add_done_callback(self._consume_refresh_result)
                self._refresh_task = task
        return await asyncio.shield(task)

    async def aclose(self) -> None:
        async with self._refresh_lock:
            self._closed = True
            task = self._refresh_task
            self._refresh_task = None
            if task is not None and not task.done():
                task.cancel()
        if task is not None:
            await asyncio.gather(task, return_exceptions=True)

    async def _fetch_validate_promote(
        self, client: KEVCatalogFetcher
    ) -> KEVCatalogSnapshot:
        try:
            fetched = await client.fetch_catalog()
            candidate = build_snapshot(
                fetched, self._now(), maximum_entries=self._maximum_entries
            )
            if not await self._promote_if_authorized(candidate):
                raise asyncio.CancelledError
            return candidate
        finally:
            async with self._refresh_lock:
                if self._refresh_task is asyncio.current_task():
                    self._refresh_task = None

    async def _promote_if_authorized(self, candidate: KEVCatalogSnapshot) -> bool:
        task = asyncio.current_task()
        async with self._refresh_lock:
            if (
                self._closed
                or task is None
                or task.cancelling()
                or self._refresh_task is not task
            ):
                return False
            active = self._snapshot
            if active is not None:
                if (
                    candidate.catalog_version == active.catalog_version
                    and candidate.content_digest != active.content_digest
                ):
                    raise KEVCatalogValidationError(
                        "Catalog version conflicts with active content"
                    )
                if candidate.date_released < active.date_released:
                    raise KEVCatalogValidationError(
                        "Catalog release predates the active snapshot"
                    )
            self._snapshot = candidate
            return True

    @staticmethod
    def _consume_refresh_result(task: asyncio.Task[KEVCatalogSnapshot]) -> None:
        try:
            task.exception()
        except asyncio.CancelledError:
            pass

    def status(self) -> KEVCatalogStatus:
        snapshot = self._snapshot
        if snapshot is None:
            availability = (
                KEVFreshnessStatus.UNAVAILABLE
                if self._refresh_attempted
                else KEVFreshnessStatus.NEVER_LOADED
            )
            return KEVCatalogStatus(
                availability=availability,
                catalog_version=None,
                date_released=None,
                fetched_at=None,
                freshness_age_seconds=None,
                count=None,
            )
        age = max(0.0, (self._now() - snapshot.fetched_at).total_seconds())
        availability = (
            KEVFreshnessStatus.FRESH
            if age <= self._freshness_seconds
            else KEVFreshnessStatus.STALE
        )
        return KEVCatalogStatus(
            availability=availability,
            catalog_version=snapshot.catalog_version,
            date_released=snapshot.date_released,
            fetched_at=snapshot.fetched_at,
            freshness_age_seconds=age,
            count=snapshot.record_count,
        )

    def lookup(self, cve_id: str) -> KEVLookupResult:
        requested = validate_kev_cve_id(cve_id)
        snapshot = self._snapshot
        if snapshot is None:
            raise KEVCatalogUnavailableError("No validated KEV snapshot is available")
        catalog_status = self.status()
        record = snapshot.records_by_cve.get(requested)
        limitations = [
            "KEV listing does not prove that a specific asset is affected or compromised.",
            "CISA due dates and required actions are published references, not a universal legal determination.",
        ]
        if record is not None:
            presence = KEVPresenceStatus.LISTED
            limitations.append(
                "The CVE is listed in the active verified CISA KEV snapshot."
            )
            if catalog_status.availability is KEVFreshnessStatus.STALE:
                limitations.append("The active snapshot is stale.")
        elif catalog_status.availability is KEVFreshnessStatus.FRESH:
            presence = KEVPresenceStatus.NOT_LISTED
            limitations.append(
                "The CVE is not listed in this fresh verified snapshot; this is not proof of no exploitation."
            )
        else:
            presence = KEVPresenceStatus.NOT_ESTABLISHED
            limitations.append(
                "Absence cannot be established because the active snapshot is stale."
            )
        return KEVLookupResult(
            cve_id=requested,
            presence=presence,
            record=record,
            catalog=catalog_status,
            limitations=tuple(limitations),
        )
