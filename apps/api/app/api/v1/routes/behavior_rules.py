import logging

from fastapi import APIRouter, HTTPException, status

from app.behavior.rule_engine import BehavioralRuleEngine, RuleEvaluationLimitError
from app.behavior.rule_registry import DEFAULT_RULE_REGISTRY, UnknownRuleError
from app.schemas.behavior_rules import (
    RuleEvaluationRequest,
    RuleEvaluationResult,
    RuleRegistryResponse,
)

logger = logging.getLogger("icylens.behavior_rules")
router = APIRouter(prefix="/behavior/rules", tags=["Behavioral Rules"])
engine = BehavioralRuleEngine(DEFAULT_RULE_REGISTRY)


@router.get(
    "",
    response_model=RuleRegistryResponse,
    summary="List the immutable built-in behavioral rule registry",
)
def list_behavioral_rules() -> RuleRegistryResponse:
    return RuleRegistryResponse(
        rules=DEFAULT_RULE_REGISTRY.rules,
        count=len(DEFAULT_RULE_REGISTRY.rules),
    )


@router.post(
    "/evaluate",
    response_model=RuleEvaluationResult,
    summary="Evaluate built-in deterministic rules over a behavioral event batch",
    responses={
        413: {"description": "The request or bounded output exceeds a resource limit."},
        422: {"description": "The event batch or rule selection is invalid."},
        503: {"description": "The deterministic evaluation budget was exceeded."},
    },
)
def evaluate_behavioral_rules(
    request: RuleEvaluationRequest,
) -> RuleEvaluationResult:
    try:
        return engine.evaluate(request)
    except UnknownRuleError as error:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "A requested behavioral rule is not registered.",
        ) from error
    except RuleEvaluationLimitError as error:
        logger.warning(
            "Behavioral rule evaluation reached a resource limit: %s",
            type(error).__name__,
        )
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Behavioral rule evaluation exceeded its resource budget.",
        ) from None
    except Exception as error:
        logger.error(
            "Behavioral rule evaluation failed with exception type %s",
            type(error).__name__,
        )
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Behavioral rule evaluation could not be completed.",
        ) from None
