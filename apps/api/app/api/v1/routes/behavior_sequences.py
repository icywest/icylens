import logging

from fastapi import APIRouter, HTTPException, status

from app.behavior.correlation import (
    TemporalCorrelationEngine,
    TemporalCorrelationLimitError,
)
from app.schemas.behavior_correlation import (
    DEFAULT_TIME_WINDOW_SECONDS,
    MAX_CORRELATION_EDGES,
    MAX_EVENTS_PER_SEQUENCE,
    MAX_RELATIONSHIPS_PER_EVENT,
    MAX_TEMPORAL_SEQUENCES,
    MAX_TIME_WINDOW_SECONDS,
    RelationshipConfidence,
    RelationshipState,
    RelationshipType,
    TemporalCorrelationRequest,
    TemporalCorrelationResult,
    TemporalCorrelationSchemaDescriptor,
)

logger = logging.getLogger("icylens.behavior_sequences")
router = APIRouter(prefix="/behavior/sequences", tags=["Behavioral Sequences"])
engine = TemporalCorrelationEngine()


@router.post(
    "/correlate",
    response_model=TemporalCorrelationResult,
    summary="Correlate bounded temporal evidence without causal inference",
    responses={
        413: {"description": "The request exceeds the behavioral body limit."},
        422: {"description": "The event batch or correlation policy is invalid."},
        503: {"description": "The bounded correlation budget was exceeded."},
    },
)
def correlate_behavioral_events(
    request: TemporalCorrelationRequest,
) -> TemporalCorrelationResult:
    try:
        return engine.correlate(request)
    except TemporalCorrelationLimitError as error:
        logger.warning(
            "Temporal correlation reached a resource limit: %s",
            type(error).__name__,
        )
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Temporal correlation exceeded its resource budget.",
        ) from None
    except Exception as error:
        logger.error(
            "Temporal correlation failed with exception type %s",
            type(error).__name__,
        )
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Temporal correlation could not be completed.",
        ) from None


@router.get(
    "/schema",
    response_model=TemporalCorrelationSchemaDescriptor,
    summary="Describe temporal correlation semantics and hard limits",
)
def get_temporal_correlation_schema() -> TemporalCorrelationSchemaDescriptor:
    return TemporalCorrelationSchemaDescriptor(
        relationship_types=tuple(RelationshipType),
        confidence_levels=tuple(RelationshipConfidence),
        relationship_states=tuple(RelationshipState),
        default_time_window_seconds=DEFAULT_TIME_WINDOW_SECONDS,
        maximum_time_window_seconds=MAX_TIME_WINDOW_SECONDS,
        maximum_relationships=MAX_CORRELATION_EDGES,
        maximum_relationships_per_event=MAX_RELATIONSHIPS_PER_EVENT,
        maximum_sequences=MAX_TEMPORAL_SEQUENCES,
        maximum_events_per_sequence=MAX_EVENTS_PER_SEQUENCE,
    )
