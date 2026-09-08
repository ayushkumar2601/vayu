"""Lightweight Server-Sent Events (SSE) stream server for live pipeline dashboard monitoring."""

from __future__ import annotations

import json
import time
from typing import AsyncGenerator
from dataclasses import dataclass, asdict


@dataclass
class PipelineEvent:
    event_type: str
    run_id: str
    data: dict[str, object]
    timestamp: float = 0.0

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.time()

    def to_sse(self) -> str:
        payload = json.dumps({
            "event": self.event_type,
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "data": self.data,
        })
        return f"event: {self.event_type}\ndata: {payload}\n\n"


class EventBroadcaster:
    """In-memory event queue manager for real-time web dashboard streaming."""

    def __init__(self) -> None:
        self.events: list[PipelineEvent] = []

    def emit(self, event_type: str, run_id: str, data: dict[str, object]) -> PipelineEvent:
        event = PipelineEvent(event_type=event_type, run_id=run_id, data=data)
        self.events.append(event)
        return event

    def get_events(self, run_id: str | None = None) -> list[PipelineEvent]:
        if run_id:
            return [e for e in self.events if e.run_id == run_id]
        return self.events


broadcaster = EventBroadcaster()
