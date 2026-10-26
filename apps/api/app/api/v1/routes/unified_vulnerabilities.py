import logging
from typing import Annotated, Any, cast

from fastapi import APIRouter, HTTPException, Path, Request, Response, status

from app.api.v1.inventory import read_asset_inventory
from app.schemas.unified_vulnerability import (
    CorrelationStatus,
    SourceStatus,
    UnifiedVulnerabilityIntelligenceResponse,
)
from app.schemas.vulnerability_interpretation import AssetInventory
from app.services.vulnerability_correlation import (
    CorrelationCapacityError,
    CorrelationDeadlineError,
    CorrelationResponseTooLargeError,
    VulnerabilityCorrelationService,
)

logger = logging.getLogger("icylens.vulnerability_correlation")

router = APIRouter(prefix="/intelligence/vulnerabilities", tags=["Threat Intelligence"])

_CVE_PATH = Path(
    pattern=r"^CVE-(1999|2\d{3})-\d{4,}$",
    max_length=32,
    description="Case-sensitive CVE identifier, for example CVE-2021-44228.",
)
_RESPONSES: dict[int | str, dict[str, Any]] = {
    200: {"description": "Complete or partial evidence correlation."},
    400: {"description": "Invalid Content-Length header."},
    413: {"description": "The inventory body exceeds the configured byte limit."},
    422: {"description": "The CVE or declared inventory is invalid."},
    429: {"description": "All usable provider paths were rate limited."},
    502: {"description": "All usable provider paths returned invalid data."},
    503: {"description": "All vulnerability intelligence sources are unavailable."},
    504: {"description": "The overall operation or all usable sources timed out."},
    500: {"description": "The correlation could not be completed safely."},
}


def _service(request: Request) -> VulnerabilityCorrelationService:
    return cast(VulnerabilityCorrelationService, request.app.state.correlation_service)


def _unavailable_status(result: UnifiedVulnerabilityIntelligenceResponse) -> int:
    statuses = {
        result.sources.nvd.status,
        result.sources.cisa_kev.status,
        result.sources.first_epss.status,
    }
    if SourceStatus.RATE_LIMITED in statuses:
        return status.HTTP_429_TOO_MANY_REQUESTS
    if SourceStatus.TIMEOUT in statuses:
        return status.HTTP_504_GATEWAY_TIMEOUT
    if SourceStatus.INVALID_RESPONSE in statuses:
        return status.HTTP_502_BAD_GATEWAY
    return status.HTTP_503_SERVICE_UNAVAILABLE


async def _correlate(
    request: Request,
    response: Response,
    cve_id: str,
    inventory: AssetInventory | None,
) -> UnifiedVulnerabilityIntelligenceResponse:
    try:
        result = await _service(request).correlate(cve_id, inventory)
    except CorrelationCapacityError as error:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Vulnerability correlation capacity is exhausted.",
        ) from error
    except CorrelationDeadlineError as error:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Vulnerability correlation timed out.",
        ) from error
    except CorrelationResponseTooLargeError as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Vulnerability correlation could not be represented safely.",
        ) from error
    except Exception as error:
        logger.error(
            "Vulnerability correlation failed with exception type %s",
            type(error).__name__,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Vulnerability correlation could not be completed.",
        ) from None
    if result.status is CorrelationStatus.UNAVAILABLE:
        response.status_code = _unavailable_status(result)
    return result


@router.get(
    "/{cve_id}",
    response_model=UnifiedVulnerabilityIntelligenceResponse,
    summary="Correlate independent vulnerability intelligence by exact CVE identity",
    responses=_RESPONSES,
)
async def get_unified_vulnerability(
    request: Request,
    response: Response,
    cve_id: Annotated[str, _CVE_PATH],
) -> UnifiedVulnerabilityIntelligenceResponse:
    return await _correlate(request, response, cve_id, None)


@router.post(
    "/{cve_id}/assessment",
    response_model=UnifiedVulnerabilityIntelligenceResponse,
    summary="Correlate vulnerability intelligence and assess declared CPE inventory",
    responses=_RESPONSES,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {"schema": AssetInventory.model_json_schema()}
            },
        }
    },
)
async def assess_unified_vulnerability(
    request: Request,
    response: Response,
    cve_id: Annotated[str, _CVE_PATH],
) -> UnifiedVulnerabilityIntelligenceResponse:
    inventory = await read_asset_inventory(request)
    return await _correlate(request, response, cve_id, inventory)
