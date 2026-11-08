"""D7: resource limits (spec §7.1).

Answers capped at 512 tokens; user messages over 2,000 characters rejected (413);
a 20-second request timeout (504; virtual clock in eval mode, a wall-clock
deadline that closes the model stream in serve and demo modes); a per-user rate
limit of 10 requests a minute with one request in flight at a time (429).
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable

STATUS_RATE = 429
STATUS_TOO_LONG = 413
STATUS_TIMEOUT = 504


def message_too_long(message: str, max_chars: int) -> bool:
    return len(message) > max_chars


class RateLimiter:
    def __init__(self, rate_per_minute: int, max_in_flight: int,
                 now: Callable[[], float] = time.monotonic, window_seconds: float = 60.0) -> None:
        self.rate = rate_per_minute
        self.max_in_flight = max_in_flight
        self.window = window_seconds
        self.now = now
        self._lock = threading.Lock()
        self._history: dict[str, deque[float]] = {}
        self._in_flight: dict[str, int] = {}

    def try_acquire(self, user: str) -> str | None:
        """Return None when admitted, else ``in_flight`` or ``rate``."""
        key = user.strip().lower()
        with self._lock:
            t = self.now()
            hist = self._history.setdefault(key, deque())
            while hist and t - hist[0] >= self.window:
                hist.popleft()
            if self._in_flight.get(key, 0) >= self.max_in_flight:
                return "in_flight"
            if len(hist) >= self.rate:
                return "rate"
            hist.append(t)
            self._in_flight[key] = self._in_flight.get(key, 0) + 1
            return None

    def release(self, user: str) -> None:
        key = user.strip().lower()
        with self._lock:
            n = self._in_flight.get(key, 0)
            if n <= 1:
                self._in_flight.pop(key, None)
            else:
                self._in_flight[key] = n - 1
