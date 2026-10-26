"""Tolerant timestamp parsing. All results are timezone-aware UTC (or ``None``)."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

_MONTHS = {
    m: i
    for i, m in enumerate(
        ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1
    )
}
_APACHE_RE = re.compile(
    r"^(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\s+([+-])(\d{2})(\d{2}))?$"
)
_SYSLOG_RE = re.compile(r"^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def ensure_utc(value: datetime) -> datetime:
    """Return an aware UTC datetime (naive values are assumed to be UTC)."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def parse_apache_timestamp(value: str) -> datetime | None:
    """Parse ``10/Oct/2023:13:55:36 +0200`` (Common/Combined Log Format)."""
    match = _APACHE_RE.match(value.strip())
    if not match:
        return None
    day, mon, year, hh, mm, ss, sign, oh, om = match.groups()
    month = _MONTHS.get(mon.lower())
    if month is None:
        return None
    try:
        parsed = datetime(int(year), month, int(day), int(hh), int(mm), int(ss), tzinfo=timezone.utc)
    except ValueError:
        return None
    if sign:
        offset = timedelta(hours=int(oh), minutes=int(om))
        parsed = parsed - offset if sign == "+" else parsed + offset
    return parsed


def parse_syslog_timestamp(value: str, year: int) -> datetime | None:
    """Parse ``Oct 10 13:55:36`` (no year/timezone: UTC and ``year`` are assumed)."""
    match = _SYSLOG_RE.match(value.strip())
    if not match:
        return None
    mon, day, hh, mm, ss = match.groups()
    month = _MONTHS.get(mon.lower())
    if month is None:
        return None
    try:
        return datetime(year, month, int(day), int(hh), int(mm), int(ss), tzinfo=timezone.utc)
    except ValueError:
        return None


def parse_iso_timestamp(value: str) -> datetime | None:
    """Parse ISO-8601 timestamps (rsyslog high precision format, ``Z`` suffix...)."""
    text = value.strip()
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    text = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", text)
    try:
        return ensure_utc(datetime.fromisoformat(text))
    except ValueError:
        return None


class SyslogClock:
    """Resolves year-less syslog timestamps, handling the December -> January rollover."""

    def __init__(self, default_year: int, reference: datetime | None = None) -> None:
        self.year = default_year
        self._reference = reference
        self._last_month: int | None = None
        self._first = True

    def resolve(self, text: str) -> datetime | None:
        if text[:1].isdigit():
            return parse_iso_timestamp(text)
        parsed = parse_syslog_timestamp(text, self.year)
        if parsed is None:
            return None
        if self._first and self._reference is not None:
            # A log whose first line lies after the file mtime belongs to the previous year.
            if parsed > self._reference + timedelta(days=1):
                self.year -= 1
                parsed = parse_syslog_timestamp(text, self.year) or parsed
        self._first = False
        month = parsed.month
        if self._last_month is not None and self._last_month - month > 6:
            self.year += 1
            parsed = parse_syslog_timestamp(text, self.year) or parsed
        self._last_month = month
        return parsed
