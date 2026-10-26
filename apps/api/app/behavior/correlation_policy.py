from __future__ import annotations

from datetime import datetime
from typing import Literal, TypeAlias

from app.schemas.behavior import EventUnion
from app.schemas.behavior_correlation import CorrelationPolicy, WindowAssessment

ProcessingTimePolicy: TypeAlias = Literal["requested", "latest_received_at"]


def resolve_processing_time(
    policy: CorrelationPolicy, events: tuple[EventUnion, ...]
) -> tuple[datetime, ProcessingTimePolicy]:
    if policy.processing_time is not None:
        return policy.processing_time, "requested"
    return max(event.provenance.received_at for event in events), "latest_received_at"


def assess_window(delta_seconds: float, policy: CorrelationPolicy) -> WindowAssessment:
    if abs(delta_seconds) <= policy.time_window_seconds:
        return WindowAssessment.WITHIN
    return WindowAssessment.OUTSIDE
