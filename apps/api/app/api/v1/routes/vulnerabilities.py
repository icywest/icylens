import logging
from typing import Annotated, cast

from fastapi import APIRouter, HTTPException, Path, Request, status

from app.integrations.nvd.client import (
    NVDClient,
    NVDInvalidResponseError,
    NVDNotFoundError,
    NVDRateLimitError,
    NVDTimeoutError,
    NVDUnavailableError,
)
from app.schemas.vulnerability import VulnerabilityRecord
from app.services.vulnerability_intelligence import VulnerabilityIntelligenceService

logger = logging.getLogger("icylens.vulnerability_intelligence")

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])


@router.get(
    "/{cve_id}",
    response_model=VulnerabilityRecord,
    summary="Retrieve and normalize one official NVD CVE record",
    responses={
        404: {"description": "NVD returned a valid response with no matching CVE."},
        422: {"description": "The CVE identifier does not match the public contract."},
        429: {"description": "The local or upstream NVD request budget is exhausted."},
        502: {"description": "NVD returned an invalid or inconsistent response."},
        503: {"description": "NVD is temporarily unavailable or denied the request."},
        504: {"description": "The NVD request timed out."},
        500: {"description": "The lookup could not be completed."},
    },
)
async def get_vulnerability(
    request: Request,
    cve_id: Annotated[
        str,
        Path(
            pattern=r"^CVE-(1999|2\d{3})-\d{4,}$",
            max_length=32,
            description="Case-sensitive CVE identifier, for example CVE-2021-44228.",
        ),
    ],
) -> VulnerabilityRecord:
    client = cast(NVDClient, request.app.state.nvd_client)
    service = VulnerabilityIntelligenceService(client)
    try:
        return await service.get_cve(cve_id)
    except NVDNotFoundError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="CVE not found."
        ) from error
    except NVDRateLimitError as error:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="NVD request capacity is temporarily exhausted.",
        ) from error
    except NVDTimeoutError as error:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="NVD request timed out.",
        ) from error
    except NVDInvalidResponseError as error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="NVD returned an invalid response.",
        ) from error
    except NVDUnavailableError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="NVD is temporarily unavailable.",
        ) from error
    except Exception as error:
        logger.error(
            "Vulnerability lookup failed with exception type %s",
            type(error).__name__,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Vulnerability lookup could not be completed.",
        ) from None
