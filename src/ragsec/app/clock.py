"""Per-turn timing and the virtual clock (spec §10.2).

Virtual latency = measured wall-clock time of the non-model stages + for each
model call, the ``prompt_eval_duration`` and ``eval_duration`` Ollama reported
when that generation was made (stored with the generation in the cache). A cache
hit therefore scores exactly like the fresh call that made it.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field


@dataclass
class TurnClock:
    now: Callable[[], float] = time.perf_counter
    started: float = 0.0
    stage_wall: dict[str, float] = field(default_factory=dict)
    model_recorded: list[float] = field(default_factory=list)
    model_wall: list[float] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.started = self.now()

    @contextmanager
    def stage(self, name: str) -> Iterator[None]:
        t0 = self.now()
        try:
            yield
        finally:
            self.stage_wall[name] = self.stage_wall.get(name, 0.0) + (self.now() - t0)

    def add_model_call(self, recorded_seconds: float, wall_seconds: float) -> None:
        self.model_recorded.append(recorded_seconds)
        self.model_wall.append(wall_seconds)

    def non_model_seconds(self) -> float:
        return sum(self.stage_wall.values())

    def virtual_latency(self) -> float:
        return self.non_model_seconds() + sum(self.model_recorded)

    def wall_elapsed(self) -> float:
        return self.now() - self.started

    def snapshot(self) -> dict[str, object]:
        return {
            "stage_wall_seconds": {k: round(v, 6) for k, v in self.stage_wall.items()},
            "model_recorded_seconds": [round(v, 6) for v in self.model_recorded],
            "model_wall_seconds": [round(v, 6) for v in self.model_wall],
            "virtual_latency_seconds": round(self.virtual_latency(), 6),
            "wall_seconds": round(self.wall_elapsed(), 6),
        }
