from app.intelligence.kev_catalog import KEVCatalogStore
from app.schemas.kev import KEVCatalogStatus, KEVLookupResult


class KEVIntelligenceService:
    def __init__(self, store: KEVCatalogStore) -> None:
        self._store = store

    def status(self) -> KEVCatalogStatus:
        return self._store.status()

    def lookup(self, cve_id: str) -> KEVLookupResult:
        return self._store.lookup(cve_id)
