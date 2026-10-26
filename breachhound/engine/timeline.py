"""Chronological timeline construction."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone

from breachhound.core.models import Finding, TimelineEvent

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def sort_key(finding: Finding) -> tuple[int, datetime, str]:
    ts = finding.timestamp
    return (0, ts, finding.id) if ts else (1, _EPOCH, finding.id)


def build_timeline(
    findings: Sequence[Finding], collapse_seconds: float = 60.0
) -> list[TimelineEvent]:
    """Sort findings chronologically and collapse repeated (ip, category) bursts."""
    events: list[TimelineEvent] = []
    open_events: dict[tuple[str | None, str, str], TimelineEvent] = {}
    for f in sorted(findings, key=sort_key):
        key = (f.ip, f.category.value, f.source.value)
        current = open_events.get(key)
        if (
            current is not None
            and f.timestamp is not None
            and current.timestamp is not None
            and (f.timestamp - current.timestamp).total_seconds() <= collapse_seconds
            and f.title == current.description.split(" (x", 1)[0]
        ):
            current.count += 1
            current.finding_ids.append(f.id)
            current.description = f"{f.title} (x{current.count})"
            if f.severity.rank > current.severity.rank:
                current.severity = f.severity
            continue
        event = TimelineEvent(
            timestamp=f.timestamp,
            description=f.title,
            severity=f.severity,
            category=f.category,
            source=f.source,
            ip=f.ip,
            finding_ids=[f.id],
            approximate=f.timestamp is None,
        )
        events.append(event)
        open_events[key] = event
    return events
