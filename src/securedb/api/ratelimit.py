"""Per-API-key fixed-window rate limiting.

In-process only: with several workers each enforces its own window. A shared store
(e.g. Redis) would be needed for horizontal scaling (spec §1.6, out of scope).
"""

import math
import threading
import time
from collections.abc import Callable

from securedb.errors import RateLimited


class FixedWindowRateLimiter:
    def __init__(
        self,
        limit: int,
        window_seconds: int = 60,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if limit < 1 or window_seconds < 1:
            raise ValueError("limit and window_seconds must be positive")
        self._limit = limit
        self._window = window_seconds
        self._clock = clock
        self._counts: dict[str, tuple[int, int]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str) -> None:
        """Count one request for `key`; raise RateLimited once the window's limit is used."""
        now = self._clock()
        window = int(now // self._window)
        with self._lock:
            current_window, count = self._counts.get(key, (window, 0))
            if current_window != window:
                count = 0
            count += 1
            self._counts[key] = (window, count)
            if len(self._counts) > 100_000:  # bound memory: drop stale windows
                self._counts = {k: v for k, v in self._counts.items() if v[0] == window}
        if count > self._limit:
            retry_after = math.ceil((window + 1) * self._window - now)
            raise RateLimited(retry_after=max(retry_after, 1))
