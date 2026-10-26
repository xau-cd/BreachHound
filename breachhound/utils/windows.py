"""Sliding-window burst detection shared by the web and auth analyzers."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime

_MAX_SAMPLES = 5
_GC_THRESHOLD = 50_000


@dataclass
class Burst:
    """A group of >= ``threshold`` events for one key within ``window`` seconds."""

    key: str
    start: datetime
    end: datetime
    count: int
    first_line: int
    last_line: int
    users: set[str] = field(default_factory=set)
    samples: list[tuple[int, str]] = field(default_factory=list)

    def add_sample(self, lineno: int, raw: str) -> None:
        if len(self.samples) < _MAX_SAMPLES:
            self.samples.append((lineno, raw))


class BurstTracker:
    """Streaming burst detector. The window is inclusive and memory stays bounded."""

    def __init__(self, threshold: int, window_seconds: float) -> None:
        if threshold < 2:
            raise ValueError("threshold must be >= 2")
        if window_seconds <= 0:
            raise ValueError("window must be > 0")
        self.threshold = threshold
        self.window = float(window_seconds)
        self._recent: dict[str, deque[tuple[datetime, int, str | None, str]]] = {}
        self._active: dict[str, Burst] = {}
        self._latest: dict[str, Burst] = {}
        self._closed: list[Burst] = []

    def add(
        self, key: str, ts: datetime, lineno: int, user: str | None = None, raw: str = ""
    ) -> None:
        recent = self._recent.setdefault(key, deque(maxlen=10_000))
        while recent and (ts - recent[0][0]).total_seconds() > self.window:
            recent.popleft()
        active = self._active.get(key)
        if active is not None and (ts - active.end).total_seconds() > self.window:
            self._closed.append(active)
            del self._active[key]
            active = None
        recent.append((ts, lineno, user, raw))
        if active is not None:
            active.end = max(active.end, ts)
            active.count += 1
            active.last_line = lineno
            if user:
                active.users.add(user)
            active.add_sample(lineno, raw)
        elif len(recent) >= self.threshold:
            burst = Burst(
                key=key,
                start=recent[0][0],
                end=ts,
                count=len(recent),
                first_line=recent[0][1],
                last_line=lineno,
            )
            for _, line_no, line_user, line_raw in recent:
                if line_user:
                    burst.users.add(line_user)
                burst.add_sample(line_no, line_raw)
            self._active[key] = burst
            self._latest[key] = burst
        if len(self._recent) > _GC_THRESHOLD:
            self._gc(ts)

    def latest(self, key: str) -> Burst | None:
        """Most recent burst (active or closed) for ``key``."""
        return self._latest.get(key)

    def finish(self) -> list[Burst]:
        """Close every active burst and return all bursts ordered by start time."""
        self._closed.extend(self._active.values())
        self._active.clear()
        bursts, self._closed = self._closed, []
        return sorted(bursts, key=lambda b: (b.start, b.key))

    def _gc(self, now: datetime) -> None:
        stale = [
            k
            for k, dq in self._recent.items()
            if k not in self._active and (not dq or (now - dq[-1][0]).total_seconds() > self.window)
        ]
        for key in stale:
            del self._recent[key]
