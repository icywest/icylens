import logging

from fastapi import APIRouter, HTTPException, Request, status

from app.attack.catalog import ATTACKCatalogStore
from app.behavior.attack_mapping_registry import (
    MappingPolicyValidationError,
    UnknownMappingPolicyError,
)
from app.behavior.correlation import TemporalCorrelationLimitError
from app.behavior.rule_engine import RuleEvaluationLimitError
from app.schemas.attack_mapping import (
    AttackMappingAssessment,
    AttackMappingPolicyRegistryResponse,
    AttackMappingRequest,
)
from app.services.attack_mapping import (
    AttackMappingCapacity,
    AttackMappingCapacityError,
    AttackMappingLimitError,
    AttackMappingService,
    evaluate_attack_mapping,
)

logger = logging.getLogger("icylens.behavior_attack_mapping")
router = APIRouter(prefix="/behavior/attack", tags=["Behavioral ATT&CK Mapping"])


@router.get(
    "/policies",
    response_model=AttackMappingPolicyRegistryResponse,
    summary="List immutable evidence-grounded ATT&CK mapping policies",
)
def list_attack_mapping_policies(
    request: Request,
) -> AttackMappingPolicyRegistryResponse:
    store: ATTACKCatalogStore = request.app.state.attack_store
    try:
        return AttackMappingService(store).policy_registry()
    except MappingPolicyValidationError as error:
        logger.error(
            "ATT&CK mapping policy validation failed with exception type %s",
            type(error).__name__,
        )
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "ATT&CK mapping policies could not be validated.",
        ) from None


@router.post(
    "/map",
    response_model=AttackMappingAssessment,
    summary="Assess bounded behavioral evidence against trusted ATT&CK policies",
    responses={
        413: {"description": "The request exceeds the behavioral body limit."},
        422: {"description": "The event batch or policy selection is invalid."},
        429: {"description": "The bounded mapping capacity is exhausted."},
        503: {"description": "The bounded mapping budget was exceeded."},
    },
)
async def map_behavioral_evidence(
    request: Request, payload: AttackMappingRequest
) -> AttackMappingAssessment:
    store: ATTACKCatalogStore = request.app.state.attack_store
    capacity: AttackMappingCapacity = request.app.state.attack_mapping_capacity
    service = AttackMappingService(store)
    try:
        return await evaluate_attack_mapping(service, payload, capacity)
    except UnknownMappingPolicyError as error:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "A requested ATT&CK mapping policy is not registered.",
        ) from error
    except AttackMappingCapacityError as error:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "ATT&CK mapping capacity is exhausted.",
        ) from error
    except (
        AttackMappingLimitError,
        RuleEvaluationLimitError,
        TemporalCorrelationLimitError,
    ) as error:
        logger.warning(
            "ATT&CK mapping reached a resource limit: %s", type(error).__name__
        )
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "ATT&CK mapping exceeded its resource budget.",
        ) from None
    except Exception as error:
        logger.error(
            "ATT&CK mapping failed with exception type %s", type(error).__name__
        )
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "ATT&CK mapping could not be completed.",
        ) from None
