from __future__ import annotations

import asyncio
import json

from app.core.config import get_settings
from app.integrations.first_epss.client import EPSSClient, EPSSClientError
from app.services.epss_intelligence import EPSSIntelligenceService

_SMOKE_CVE = "CVE-2021-44228"


async def main() -> int:
    settings = get_settings()
    client = EPSSClient(settings)
    service = EPSSIntelligenceService(settings, client)
    try:
        result = await service.lookup(_SMOKE_CVE)
    except EPSSClientError as error:
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
                "cve_id": result.cve_id,
                "lookup_status": result.status.value,
                "score": None if result.score is None else str(result.score),
                "percentile": (
                    None if result.percentile is None else str(result.percentile)
                ),
                "score_date": (
                    None if result.score_date is None else result.score_date.isoformat()
                ),
                "freshness": result.freshness.value,
                "retrieved_at": result.provenance.retrieved_at.isoformat(),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
