"""Per-process request throttling for the public API.

A fixed-window counter keyed by client identity (IP, or `X-Forwarded-For` when
behind a proxy). Deliberately dependency-free and in-memory: correct for a
single-process deployment, and honest about not being more than that --
running several worker processes or several instances multiplies the
effective limit, because each process holds its own counters. Scaling past
one process means swapping the dict below for a shared store (Redis is the
obvious choice) behind this same `check()` interface; nothing that calls it
needs to change.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from threading import Lock


class RateLimitExceeded(RuntimeError):
    """The caller is over their limit. Carries how long they should wait."""

    def __init__(self, retry_after: float):
        self.retry_after = retry_after
        super().__init__(f"rate limit exceeded, retry after {retry_after:.0f}s")


@dataclass
class FixedWindowLimiter:
    limit: int
    window_seconds: float = 60.0
    _lock: Lock = field(default_factory=Lock, repr=False, compare=False)
    _buckets: dict[str, tuple[int, float]] = field(default_factory=dict, repr=False, compare=False)

    def check(self, key: str, now: float | None = None) -> None:
        """Record one call under `key`. Raises RateLimitExceeded once over limit."""
        now = time.time() if now is None else now
        with self._lock:
            count, start = self._buckets.get(key, (0, now))
            if now - start >= self.window_seconds:
                count, start = 0, now
            count += 1
            self._buckets[key] = (count, start)
            if count > self.limit:
                raise RateLimitExceeded(max(self.window_seconds - (now - start), 1.0))

    def reset(self) -> None:
        """Test hook: clear all counters."""
        with self._lock:
            self._buckets.clear()
