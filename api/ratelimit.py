"""A small in-memory, per-client sliding-window rate limiter.

Each client key (the client IP) keeps the timestamps of its recent requests.
A request is allowed if fewer than `limit` of them fall inside the window.

Limits of this design (fine for one process, say so before scaling out):
- State lives in this process. With N uvicorn workers or N containers, each
  has its own counts, so a client effectively gets N times the limit.
- A restart forgets every count.
- Behind a reverse proxy every request comes from the proxy's IP, so all
  users share one bucket. Trust X-Forwarded-For only from a known proxy.
A shared store (Redis, or the proxy's own limiter) fixes all three.
"""

import math
import threading
import time
from collections import deque
from collections.abc import Callable

# Forget clients that have been quiet for a full window once there are this
# many, so a flood of distinct IPs can't grow memory without bound.
PRUNE_THRESHOLD = 10_000


class RateLimiter:
    def __init__(
        self,
        limit: int,
        window_seconds: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.limit = limit
        self.window_seconds = window_seconds
        self.clock = clock  # Tests pass a fake clock, as with Cache.
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str, cost: int = 1) -> int | None:
        """Record a request worth `cost` hits. Returns None if allowed, else seconds until a retry would be.

        A cost above the limit can never be allowed; callers refuse those first.
        """
        now = self.clock()
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] >= self.window_seconds:
                hits.popleft()

            excess = len(hits) + cost - self.limit
            if excess > 0:
                # Wait until enough of the oldest hits have left the window.
                oldest_needed = hits[min(excess, len(hits)) - 1] if hits else now
                return max(1, math.ceil(self.window_seconds - (now - oldest_needed)))

            hits.extend([now] * cost)
            if len(self._hits) > PRUNE_THRESHOLD:
                self._prune(now)
            return None

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()

    def _prune(self, now: float) -> None:
        quiet = [k for k, hits in self._hits.items() if not hits or now - hits[-1] >= self.window_seconds]
        for key in quiet:
            del self._hits[key]
