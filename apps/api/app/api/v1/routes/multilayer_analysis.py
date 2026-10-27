import logging

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from starlette.responses import Response

from app.multilayer.admission import MultilayerAdmissionError
from app.multilayer.service import (
    MultilayerAnalysisCapacityError,
    MultilayerAnalysisConsistencyError,
    MultilayerAnalysisLimitError,
    MultilayerAnalysisService,
    MultilayerAnalysisTimeoutError,
    execute_multilayer_analysis,
)
from app.schemas.evidence import EvidenceDomain
from app.schemas.multilayer_analysis import (
    MultilayerAnalysisRequest,
    MultilayerAnalysisResponse,
    MultilayerInputType,
    MultilayerResourceLimits,
    MultilayerResponseMode,
    MultilayerSchemaDescriptor,
)
from app.services.synchronous_workers import SynchronousWorkerManager
from app.sufficiency.rules import DEFAULT_SUFFICIENCY_POLICY_REGISTRY

logger = logging.getLogger("icylens.multilayer_analysis")


class RedactedValidationRoute(APIRoute):
    def get_route_handler(self):  # type: ignore[no-untyped-def]
        original = super().get_route_handler()

        async def redacted(request: Request) -> Response:
            try:
                return await original(request)
            except RequestValidationError as error:
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_CONTENT,
                    "The multilayer request schema is invalid.",
                ) from error

        return redacted


router = APIRouter(
    prefix="/multilayer",
    tags=["Unified Multilayer Analysis"],
    route_class=RedactedValidationRoute,
)


@router.post(
    "/analyze",
    response_model=MultilayerAnalysisResponse,
    summary="Analyze bounded client-declared evidence through Phase 06",
    responses={
        413: {"description": "The request exceeds the multilayer body limit."},
        422: {"description": "The request or declared source selection is invalid."},
        429: {"description": "The bounded synchronous worker capacity is exhausted."},
        500: {"description": "Internal result consistency validation failed."},
        503: {"description": "A multilayer resource limit was exceeded."},
        504: {"description": "The bounded multilayer operation timed out."},
    },
)
async def analyze_multilayer(
    request: Request, payload: MultilayerAnalysisRequest
) -> MultilayerAnalysisResponse:
    capacity: SynchronousWorkerManager = request.app.state.multilayer_analysis_capacity
    service = MultilayerAnalysisService()
    try:
        return await execute_multilayer_analysis(
            lambda: service.analyze(payload), capacity
        )
    except MultilayerAdmissionError as error:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "A declared source or assertion reference is invalid.",
        ) from error
    except MultilayerAnalysisCapacityError as error:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Multilayer analysis capacity is exhausted.",
        ) from error
    except MultilayerAnalysisTimeoutError as error:
        logger.warning("Multilayer analysis reached its execution deadline.")
        raise HTTPException(
            status.HTTP_504_GATEWAY_TIMEOUT,
            "Multilayer analysis timed out.",
        ) from error
    except MultilayerAnalysisLimitError as error:
        logger.warning("Multilayer analysis reached a resource limit.")
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Multilayer analysis exceeded its resource budget.",
        ) from error
    except MultilayerAnalysisConsistencyError as error:
        logger.error("Multilayer internal consistency validation failed.")
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Multilayer analysis could not be completed.",
        ) from error
    except Exception as error:
        logger.error(
            "Multilayer analysis failed with exception type %s",
            type(error).__name__,
        )
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Multilayer analysis could not be completed.",
        ) from None


@router.get(
    "/schema",
    response_model=MultilayerSchemaDescriptor,
    summary="Describe safe multilayer input modes, policies, and limits",
)
def get_multilayer_schema() -> MultilayerSchemaDescriptor:
    return MultilayerSchemaDescriptor(
        input_modes=tuple(MultilayerInputType),
        response_modes=tuple(MultilayerResponseMode),
        supported_assertion_ids=tuple(
            item.assertion_id for item in DEFAULT_SUFFICIENCY_POLICY_REGISTRY.assertions
        ),
        supported_domains=(
            EvidenceDomain.STATIC,
            EvidenceDomain.SYNTHETIC_ML,
            EvidenceDomain.VULNERABILITY,
        ),
        limits=MultilayerResourceLimits(),
        limitations=(
            "All accepted observations are client-declared and origin-unverified.",
            "No EvidenceBatch or precomputed identity, correlation, sufficiency, or trace result is accepted.",
            "No provider lookup, model execution, threat scoring, causal inference, persistence, or response action is performed.",
            "A sufficient assessment supports only its registered assertion.",
        ),
    )
