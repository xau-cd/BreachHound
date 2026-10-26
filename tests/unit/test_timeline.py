from __future__ import annotations

from datetime import timedelta

from helpers import T0

from breachhound.core.enums import Category, Severity, SourceType
from breachhound.core.models import Finding
from breachhound.engine.timeline import build_timeline


def mk(fid, offset, ip="198.51.100.1", cat=Category.SQL_INJECTION, sev=Severity.HIGH):
    ts = None if offset is None else T0 + timedelta(seconds=offset)
    return Finding(id=fid, category=cat, severity=sev, title=cat.value, source=SourceType.WEB, confidence=0.9, timestamp=ts, ip=ip)


def test_sorted_and_undated_last():
    events = build_timeline([mk("c", None, "1.1.1.1"), mk("b", 500, "2.2.2.2"), mk("a", 10, "3.3.3.3")], collapse_seconds=0)
    assert [e.finding_ids[0] for e in events] == ["a", "b", "c"]
    assert events[-1].approximate and events[0].timestamp < events[1].timestamp


def test_collapse_bursts():
    events = build_timeline([mk(str(i), i) for i in range(10)], 60)
    assert len(events) == 1 and events[0].count == 10 and "x10" in events[0].description


def test_collapse_respects_window_ip_and_category():
    events = build_timeline([mk("a", 0), mk("b", 500), mk("c", 5, ip="9.9.9.9"), mk("d", 6, cat=Category.XSS)], 60)
    assert len(events) == 4


def test_empty():
    assert build_timeline([]) == []
