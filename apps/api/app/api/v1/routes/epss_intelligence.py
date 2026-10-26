import logging
from typing import Annotated, cast

from fastapi import APIRouter, HTTPException, Path, Request, status

from app.integrations.first_epss.client import (
    EPSSInvalidResponseError,
    EPSSRateLimitError,
    EPSSTimeoutError,
    EPSSUnavailableError,
)
from app.schemas.epss import EPSSLookupResult
from app.services.epss_intelligence import EPSSIntelligenceService

logger = logging.getLogger("icylens.epss_intelligence")

router = APIRouter(prefix="/intelligence/epss", tags=["Threat Intelligence"])

_CVE_PATH = Path(
    pattern=r"^CVE-(1999|2[0-9]{3})-[0-9]{4,19}$",
    max_length=32,
    description="Case-sensitive CVE identifier, for example CVE-2021-44228.",
)


def _service(request: Request) -> EPSSIntelligenceService:
    return cast(EPSSIntelligenceService, request.app.state.epss_service)


@router.get(
    "/{cve_id}",
    response_model=EPSSLookupResult,
    summary="Look up the current FIRST EPSS score for one CVE",
    responses={
        422: {"description": "The CVE identifier is invalid."},
        429: {"description": "The local or provider request limit was reached."},
        502: {"description": "FIRST returned an invalid response."},
        503: {"description": "FIRST is temporarily unavailable."},
        504: {"description": "The FIRST request exceeded its deadline."},
        500: {"description": "The lookup could not be completed."},
    },
)
async def get_epss_record(
    request: Request, cve_id: Annotated[str, _CVE_PATH]
) -> EPSSLookupResult:
    try:
        return await _service(request).lookup(cve_id)
    except EPSSRateLimitError as error:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="EPSS request limit was reached.",
        ) from error
    except EPSSInvalidResponseError as error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="FIRST EPSS returned an invalid response.",
        ) from error
    except EPSSUnavailableError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="FIRST EPSS is temporarily unavailable.",
        ) from error
    except EPSSTimeoutError as error:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="FIRST EPSS request timed out.",
        ) from error
    except Exception as error:
        logger.error("EPSS lookup failed with exception type %s", type(error).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="EPSS lookup could not be completed.",
        ) from None
