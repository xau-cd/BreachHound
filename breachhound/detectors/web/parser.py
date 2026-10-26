"""Nginx/Apache Common and Combined Log Format parser."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from breachhound.core.exceptions import BreachHoundError
from breachhound.utils.filesystem import iter_lines
from breachhound.utils.timestamps import parse_apache_timestamp

_LOG_RE = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+"
    r'"(?P<request>(?:[^"\\]|\\.)*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>(?:[^"\\]|\\.)*)"\s+"(?P<agent>(?:[^"\\]|\\.)*)")?'
)
_SALVAGE_RE = re.compile(r"^(?P<ip>[0-9A-Fa-f:.]{3,45})\s+\S+\s+\S+\s+\[")


@dataclass
class WebLogEntry:
    ip: str
    ident_user: str | None
    timestamp: datetime | None
    method: str | None
    target: str
    protocol: str | None
    status: int | None
    size: int | None
    referer: str | None
    user_agent: str | None
    raw: str
    lineno: int
    parse_quality: str = "parsed"  # parsed | raw


def parse_request(request: str) -> tuple[str | None, str, str | None]:
    """Split ``GET /path HTTP/1.1`` tolerating spaces inside malicious targets."""
    parts = request.split(" ")
    if len(parts) >= 3 and parts[-1].upper().startswith("HTTP/"):
        return parts[0], " ".join(parts[1:-1]), parts[-1]
    if len(parts) == 2:
        return parts[0], parts[1], None
    return None, request, None


def _opt(value: str | None) -> str | None:
    return None if value in (None, "", "-") else value


def parse_line(line: str, lineno: int = 0) -> WebLogEntry | None:
    """Parse a log line. Returns ``None`` when the format does not match."""
    match = _LOG_RE.match(line)
    if not match:
        return None
    method, target, protocol = parse_request(match["request"])
    size = match["size"]
    return WebLogEntry(
        ip=match["ip"],
        ident_user=_opt(match["user"]),
        timestamp=parse_apache_timestamp(match["ts"]),
        method=method,
        target=target,
        protocol=protocol,
        status=int(match["status"]),
        size=int(size) if size.isdigit() else None,
        referer=_opt(match["referer"]),
        user_agent=_opt(match["agent"]),
        raw=line,
        lineno=lineno,
    )


def salvage_line(line: str, lineno: int = 0) -> WebLogEntry | None:
    """Best-effort entry for malformed/truncated lines so payloads are still scanned."""
    match = _SALVAGE_RE.match(line)
    if not match:
        return None
    return WebLogEntry(
        ip=match["ip"],
        ident_user=None,
        timestamp=None,
        method=None,
        target=line[match.end() :],
        protocol=None,
        status=None,
        size=None,
        referer=None,
        user_agent=None,
        raw=line,
        lineno=lineno,
        parse_quality="raw",
    )


def looks_like_web_log(path: Path, sample: int = 50) -> bool:
    """Sniff the first lines: at least half must parse as CLF/Combined."""
    seen = parsed = 0
    try:
        for _, line, _ in iter_lines(path, 4096):
            if not line.strip():
                continue
            seen += 1
            parsed += parse_line(line) is not None
            if seen >= sample:
                break
    except BreachHoundError:
        return False
    return seen > 0 and parsed * 2 >= seen
