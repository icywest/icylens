import logging

from fastapi import APIRouter, HTTPException, status

from app.behavior.generator import generate_scenario
from app.behavior.validation import validate_event_batch
from app.schemas.behavior import (
    MAX_ATTRIBUTE_DEPTH,
    MAX_BATCH_BYTES,
    MAX_EVENT_BYTES,
    MAX_EVENTS_PER_BATCH,
    MAX_SYNTHETIC_EVENTS,
    BehavioralSchemaDescriptor,
    EventBatch,
    EventValidationResult,
    SyntheticScenario,
    SyntheticScenarioRequest,
)

logger = logging.getLogger("icylens.behavior")
router = APIRouter(prefix="/behavior", tags=["Behavioral Telemetry"])


@router.post(
    "/events/validate",
    response_model=EventValidationResult,
    summary="Validate a bounded batch of declared behavioral events",
    responses={
        413: {"description": "The event batch exceeds its byte limit."},
        422: {"description": "The event contract is invalid."},
    },
)
async def validate_events(batch: EventBatch) -> EventValidationResult:
    try:
        return validate_event_batch(batch)
    except Exception as error:
        logger.error(
            "Behavior validation failed with exception type %s", type(error).__name__
        )
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Behavioral validation could not be completed.",
        ) from None


@router.post(
    "/scenarios/generate",
    response_model=SyntheticScenario,
    summary="Generate deterministic offline educational telemetry",
    responses={
        413: {"description": "The generation request exceeds its byte limit."},
        422: {"description": "The scenario request is invalid."},
    },
)
async def generate_synthetic_scenario(
    specification: SyntheticScenarioRequest,
) -> SyntheticScenario:
    try:
        return generate_scenario(specification)
    except Exception as error:
        logger.error(
            "Synthetic generation failed with exception type %s", type(error).__name__
        )
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Synthetic scenario could not be generated.",
        ) from None


@router.get(
    "/schema",
    response_model=BehavioralSchemaDescriptor,
    summary="Describe the behavioral event schema and hard limits",
)
def get_behavioral_schema() -> BehavioralSchemaDescriptor:
    return BehavioralSchemaDescriptor(
        event_types=("process", "file", "network", "configuration"),
        maximum_events_per_batch=MAX_EVENTS_PER_BATCH,
        maximum_synthetic_events=MAX_SYNTHETIC_EVENTS,
        maximum_event_bytes=MAX_EVENT_BYTES,
        maximum_batch_bytes=MAX_BATCH_BYTES,
        maximum_attribute_depth=MAX_ATTRIBUTE_DEPTH,
    )
