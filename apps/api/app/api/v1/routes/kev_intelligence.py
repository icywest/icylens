import logging
from typing import Annotated, cast

from fastapi import APIRouter, HTTPException, Path, Request, status

from app.intelligence.kev_catalog import (
    KEVCatalogStore,
    KEVCatalogUnavailableError,
)
from app.schemas.kev import KEVCatalogStatus, KEVLookupResult
from app.services.kev_intelligence import KEVIntelligenceService

logger = logging.getLogger("icylens.kev_intelligence")

router = APIRouter(prefix="/intelligence/kev", tags=["Threat Intelligence"])

_CVE_PATH = Path(
    pattern=r"^CVE-[0-9]{4}-[0-9]{4,19}$",
    max_length=32,
    description="Case-sensitive CVE identifier, for example CVE-2021-44228.",
)


def _service(request: Request) -> KEVIntelligenceService:
    store = cast(KEVCatalogStore, request.app.state.kev_store)
    return KEVIntelligenceService(store)


@router.get(
    "/status",
    response_model=KEVCatalogStatus,
    summary="Return public CISA KEV snapshot status",
)
async def get_kev_status(request: Request) -> KEVCatalogStatus:
    return _service(request).status()


@router.get(
    "/{cve_id}",
    response_model=KEVLookupResult,
    summary="Look up a CVE in the active verified CISA KEV snapshot",
    responses={
        422: {"description": "The CVE identifier is invalid."},
        503: {"description": "No validated KEV snapshot is available."},
        500: {"description": "The lookup could not be completed."},
    },
)
async def get_kev_record(
    request: Request, cve_id: Annotated[str, _CVE_PATH]
) -> KEVLookupResult:
    try:
        return _service(request).lookup(cve_id)
    except KEVCatalogUnavailableError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="CISA KEV catalog is not available.",
        ) from error
    except Exception as error:
        logger.error("KEV lookup failed with exception type %s", type(error).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="KEV lookup could not be completed.",
        ) from None
