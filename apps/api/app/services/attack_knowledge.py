from app.attack.catalog import ATTACKCatalogStore, ATTACKCatalogUnavailableError
from app.schemas.attack import (
    ATTACKCatalogStatus,
    ATTACKObjectStatus,
    ATTACKTactic,
    ATTACKTacticList,
    ATTACKTechnique,
    ATTACKTechniqueList,
)


class ATTACKKnowledgeService:
    def __init__(self, store: ATTACKCatalogStore) -> None:
        self._store = store

    def status(self) -> ATTACKCatalogStatus:
        try:
            snapshot = self._store.snapshot
        except ATTACKCatalogUnavailableError:
            return ATTACKCatalogStatus(
                available=False,
                validation_status="unavailable",
                provenance=None,
                statistics=None,
                retired_policy="retained_excluded_by_default",
            )
        return ATTACKCatalogStatus(
            available=True,
            validation_status="validated",
            provenance=snapshot.provenance,
            statistics=snapshot.statistics,
            retired_policy="retained_excluded_by_default",
        )

    @staticmethod
    def _visible(status: ATTACKObjectStatus, include_retired: bool) -> bool:
        return include_retired or status is ATTACKObjectStatus.ACTIVE

    def tactic(self, attack_id: str, include_retired: bool) -> ATTACKTactic | None:
        item = self._store.snapshot.tactics_by_id.get(attack_id)
        return item if item and self._visible(item.status, include_retired) else None

    def technique(
        self, attack_id: str, include_retired: bool
    ) -> ATTACKTechnique | None:
        item = self._store.snapshot.techniques_by_id.get(attack_id)
        return item if item and self._visible(item.status, include_retired) else None

    def tactics(
        self, offset: int, limit: int, include_retired: bool
    ) -> ATTACKTacticList:
        snapshot = self._store.snapshot
        items = tuple(
            item
            for item in snapshot.tactics_by_id.values()
            if self._visible(item.status, include_retired)
        )
        return ATTACKTacticList(
            items=items[offset : offset + limit],
            total=len(items),
            offset=offset,
            limit=limit,
            provenance=snapshot.provenance,
        )

    def techniques_for_tactic(
        self, tactic_id: str, offset: int, limit: int, include_retired: bool
    ) -> ATTACKTechniqueList:
        snapshot = self._store.snapshot
        items = tuple(
            item
            for item in snapshot.techniques_by_id.values()
            if tactic_id in item.tactic_ids
            and self._visible(item.status, include_retired)
        )
        return ATTACKTechniqueList(
            items=items[offset : offset + limit],
            total=len(items),
            offset=offset,
            limit=limit,
            provenance=snapshot.provenance,
        )

    def subtechniques(
        self, technique_id: str, offset: int, limit: int, include_retired: bool
    ) -> ATTACKTechniqueList:
        snapshot = self._store.snapshot
        items = tuple(
            item
            for item in snapshot.techniques_by_id.values()
            if item.parent_attack_id == technique_id
            and self._visible(item.status, include_retired)
        )
        return ATTACKTechniqueList(
            items=items[offset : offset + limit],
            total=len(items),
            offset=offset,
            limit=limit,
            provenance=snapshot.provenance,
        )
