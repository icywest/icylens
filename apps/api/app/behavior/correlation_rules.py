from __future__ import annotations

from collections.abc import Sequence

from app.schemas.behavior import EventUnion


def event_delta_seconds(first: EventUnion, second: EventUnion) -> float:
    return (second.timestamp - first.timestamp).total_seconds()


def windowed_runs(
    events: Sequence[EventUnion], window_seconds: int
) -> tuple[tuple[EventUnion, ...], ...]:
    """Return adjacent identity runs without bridging an out-of-window gap."""
    if not events:
        return ()
    runs: list[tuple[EventUnion, ...]] = []
    current: list[EventUnion] = [events[0]]
    for previous, event in zip(events, events[1:], strict=False):
        if event_delta_seconds(previous, event) <= window_seconds:
            current.append(event)
        else:
            if len(current) > 1:
                runs.append(tuple(current))
            current = [event]
    if len(current) > 1:
        runs.append(tuple(current))
    return tuple(runs)
