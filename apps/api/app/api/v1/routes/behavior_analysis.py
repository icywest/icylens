import logging
from collections.abc import Callable

from fastapi import APIRouter, HTTPException, Request, status

from app.attack.catalog import ATTACKCatalogStore
from app.behavior.attack_mapping_registry import UnknownMappingPolicyError
from app.behavior.correlation import TemporalCorrelationLimitError
from app.behavior.rule_engine import RuleEvaluationLimitError
from app.behavior.rule_registry import UnknownRuleError
from app.schemas.behavior import (
    MAX_BATCH_BYTES,
    MAX_EVENTS_PER_BATCH,
    MAX_SYNTHETIC_EVENTS,
)
from app.schemas.behavior_analysis import (
    MAX_UNIFIED_ANALYSIS_OUTPUT_BYTES,
    UNIFIED_ANALYSIS_MAX_CONCURRENCY,
    BehavioralAnalysisRequest,
    BehavioralAnalysisResult,
    BehavioralAnalysisSchemaDescriptor,
    BehavioralAnalysisSource,
    BehavioralAnalysisStageStatus,
    BehavioralAnalysisStatus,
    SyntheticAnalysisRequest,
)
from app.services.attack_mapping import AttackMappingLimitError
from app.services.behavior_analysis import (
    BehavioralAnalysisCapacityError,
    BehavioralAnalysisLimitError,
    BehavioralAnalysisService,
    execute_behavioral_analysis,
)
from app.services.synchronous_workers import SynchronousWorkerManager

logger = logging.getLogger("icylens.behavior_analysis")
router = APIRouter(prefix="/behavior", tags=["Unified Behavioral Analysis"])


def _service(request: Request) -> BehavioralAnalysisService:
    store: ATTACKCatalogStore = request.app.state.attack_store
    return BehavioralAnalysisService(store)


async def _execute(
    request: Request,
    operation: Callable[[], BehavioralAnalysisResult],
) -> BehavioralAnalysisResult:
    capacity: SynchronousWorkerManager = request.app.state.behavior_analysis_capacity
    try:
        return await execute_behavioral_analysis(operation, capacity)
    except (UnknownRuleError, UnknownMappingPolicyError) as error:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "A requested analysis rule or mapping policy is not registered.",
        ) from error
    except BehavioralAnalysisCapacityError as error:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Behavioral analysis capacity is exhausted.",
        ) from error
    except (
        BehavioralAnalysisLimitError,
        RuleEvaluationLimitError,
        TemporalCorrelationLimitError,
        AttackMappingLimitError,
    ) as error:
        logger.warning(
            "Unified behavioral analysis reached a resource limit: %s",
            type(error).__name__,
        )
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Behavioral analysis exceeded its resource budget.",
        ) from None
    except Exception as error:
        logger.error(
            "Unified behavioral analysis failed with exception type %s",
            type(error).__name__,
        )
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Behavioral analysis could not be completed.",
        ) from None


@router.post(
    "/analyze",
    response_model=BehavioralAnalysisResult,
    summary="Run a unified evidence-grounded behavioral assessment",
    responses={
        413: {"description": "The request exceeds the behavioral body limit."},
        422: {"description": "The event batch or bounded options are invalid."},
        429: {"description": "The bounded analysis capacity is exhausted."},
        503: {"description": "An analysis resource budget was exceeded."},
    },
)
async def analyze_behavioral_batch(
    request: Request, payload: BehavioralAnalysisRequest
) -> BehavioralAnalysisResult:
    service = _service(request)
    return await _execute(request, lambda: service.analyze(payload))


@router.post(
    "/scenarios/analyze",
    response_model=BehavioralAnalysisResult,
    summary="Generate and analyze one deterministic educational scenario",
    responses={
        413: {"description": "The scenario request exceeds its body limit."},
        422: {"description": "The scenario specification or options are invalid."},
        429: {"description": "The bounded analysis capacity is exhausted."},
        503: {"description": "An analysis resource budget was exceeded."},
    },
)
async def analyze_synthetic_scenario(
    request: Request, payload: SyntheticAnalysisRequest
) -> BehavioralAnalysisResult:
    service = _service(request)
    return await _execute(request, lambda: service.analyze_synthetic(payload))


@router.get(
    "/analysis/schema",
    response_model=BehavioralAnalysisSchemaDescriptor,
    summary="Describe unified behavioral analysis modes, states, and limits",
)
def get_behavioral_analysis_schema() -> BehavioralAnalysisSchemaDescriptor:
    return BehavioralAnalysisSchemaDescriptor(
        sources=tuple(BehavioralAnalysisSource),
        statuses=tuple(BehavioralAnalysisStatus),
        stage_statuses=tuple(BehavioralAnalysisStageStatus),
        maximum_declared_events=MAX_EVENTS_PER_BATCH,
        maximum_synthetic_events=MAX_SYNTHETIC_EVENTS,
        maximum_request_bytes=MAX_BATCH_BYTES,
        maximum_response_bytes=MAX_UNIFIED_ANALYSIS_OUTPUT_BYTES,
        maximum_concurrency=UNIFIED_ANALYSIS_MAX_CONCURRENCY,
    )
