import logging
from typing import Annotated, Any, cast

from fastapi import APIRouter, HTTPException, Path, Request, status

from app.api.v1.inventory import read_asset_inventory
from app.integrations.nvd.client import (
    NVDClient,
    NVDInvalidResponseError,
    NVDNotFoundError,
    NVDRateLimitError,
    NVDTimeoutError,
    NVDUnavailableError,
)
from app.schemas.vulnerability import VulnerabilityRecord
from app.schemas.vulnerability_interpretation import (
    ApplicabilityAssessment,
    AssetInventory,
    VulnerabilityInterpretation,
)
from app.services.vulnerability_intelligence import VulnerabilityIntelligenceService
from app.services.vulnerability_interpretation import (
    VulnerabilityInterpretationService,
)

logger = logging.getLogger("icylens.vulnerability_intelligence")

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])

_CVE_PATH = Path(
    pattern=r"^CVE-(1999|2\d{3})-\d{4,}$",
    max_length=32,
    description="Case-sensitive CVE identifier, for example CVE-2021-44228.",
)
_PROVIDER_RESPONSES: dict[int | str, dict[str, Any]] = {
    404: {"description": "NVD returned no matching CVE."},
    429: {"description": "The local or upstream request budget is exhausted."},
    502: {"description": "NVD returned an invalid or inconsistent response."},
    503: {"description": "NVD is unavailable or denied the request."},
    504: {"description": "The NVD request timed out."},
    500: {"description": "The operation could not be completed."},
}


async def _get_record(request: Request, cve_id: str) -> VulnerabilityRecord:
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
    cve_id: Annotated[str, _CVE_PATH],
) -> VulnerabilityRecord:
    return await _get_record(request, cve_id)


@router.get(
    "/{cve_id}/interpretation",
    response_model=VulnerabilityInterpretation,
    summary="Interpret source CVSS and CWE data without assessing an asset",
    responses=_PROVIDER_RESPONSES,
)
async def get_vulnerability_interpretation(
    request: Request, cve_id: Annotated[str, _CVE_PATH]
) -> VulnerabilityInterpretation:
    record = await _get_record(request, cve_id)
    return VulnerabilityInterpretationService().interpret(record)


@router.post(
    "/{cve_id}/applicability",
    response_model=ApplicabilityAssessment,
    summary="Assess NVD CPE criteria against a bounded declared inventory",
    responses={
        **_PROVIDER_RESPONSES,
        413: {"description": "The raw JSON body exceeds the configured byte limit."},
        422: {"description": "The declared inventory is invalid."},
    },
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {"schema": AssetInventory.model_json_schema()}
            },
        }
    },
)
async def assess_vulnerability_applicability(
    request: Request, cve_id: Annotated[str, _CVE_PATH]
) -> ApplicabilityAssessment:
    inventory = await read_asset_inventory(request)
    record = await _get_record(request, cve_id)
    return VulnerabilityInterpretationService().assess(record, inventory)
