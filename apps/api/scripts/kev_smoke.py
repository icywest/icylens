from __future__ import annotations

import asyncio
import json

from app.core.config import get_settings
from app.integrations.cisa_kev.client import KEVClient, KEVClientError
from app.intelligence.kev_catalog import KEVCatalogStore, KEVCatalogValidationError


async def main() -> int:
    settings = get_settings()
    client = KEVClient(settings)
    store = KEVCatalogStore(settings)
    try:
        snapshot = await store.refresh(client)
    except (KEVClientError, KEVCatalogValidationError) as error:
        print(
            json.dumps(
                {"status": "failed", "error_type": type(error).__name__},
                sort_keys=True,
            )
        )
        return 1
    finally:
        await client.aclose()
    print(
        json.dumps(
            {
                "status": "validated",
                "catalog_version": snapshot.catalog_version,
                "date_released": snapshot.date_released.isoformat(),
                "record_count": snapshot.record_count,
                "content_digest": snapshot.content_digest,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
