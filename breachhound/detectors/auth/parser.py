"""syslog-style authentication log parser (sshd, sudo, su, account tools)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path

from breachhound.core.exceptions import BreachHoundError
from breachhound.utils.filesystem import iter_lines
from breachhound.utils.timestamps import SyslogClock


class AuthEventKind(str, Enum):
    FAILED_LOGIN = "FAILED_LOGIN"
    ACCEPTED_LOGIN = "ACCEPTED_LOGIN"
    INVALID_USER = "INVALID_USER"
    CONNECTION = "CONNECTION"
    PAM_FAILURE = "PAM_FAILURE"
    SUDO_COMMAND = "SUDO_COMMAND"
    SUDO_FAILURE = "SUDO_FAILURE"
    SUDO_NOT_IN_SUDOERS = "SUDO_NOT_IN_SUDOERS"
    SUDO_INCORRECT_ATTEMPTS = "SUDO_INCORRECT_ATTEMPTS"
    SU_SESSION = "SU_SESSION"
    USER_ADDED = "USER_ADDED"
    GROUP_MEMBER_ADDED = "GROUP_MEMBER_ADDED"


@dataclass
class AuthEvent:
    kind: AuthEventKind
    timestamp: datetime | None
    host: str
    process: str
    raw: str
    lineno: int
    user: str | None = None
    ip: str | None = None
    port: int | None = None
    auth_method: str | None = None
    command: str | None = None
    target_user: str | None = None
    group: str | None = None
    extra: dict[str, str] = field(default_factory=dict)


_HEADER_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    r"|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+(?P<proc>[A-Za-z0-9_.\-/]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
_IP = r"(?P<ip>[0-9A-Fa-f:.]+)"
_FAILED = re.compile(
    rf"^Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from {_IP}(?: port (?P<port>\d+))?"
)
_ACCEPTED = re.compile(
    rf"^Accepted (?P<method>\S+) for (?P<user>\S+) from {_IP}(?: port (?P<port>\d+))?"
)
_INVALID = re.compile(rf"^Invalid user (?P<user>.*?) from {_IP}(?: port (?P<port>\d+))?")
_CONN = re.compile(
    r"^(?:Connection closed by|Disconnected from|Connection reset by)(?: (?:invalid|authenticating))?"
    rf"(?: user (?P<user>\S+))? {_IP} port (?P<port>\d+)"
)
_CONN2 = re.compile(
    rf"^(?:Did not receive identification string from|Received disconnect from|Unable to negotiate with) {_IP}"
)
_PAM = re.compile(r"^pam_unix\((?P<svc>[^:)]+):auth\): authentication failure;(?P<rest>.*)$")
_SUDO_CMD = re.compile(
    r"^(?P<user>\S+)\s*:\s*(?:TTY=(?P<tty>\S+)\s*;\s*)?PWD=(?P<pwd>.*?)\s*;\s*USER=(?P<target>\S+)\s*;\s*"
    r"(?:TSID=\S+\s*;\s*)?COMMAND=(?P<cmd>.*)$"
)
_SUDO_INCORRECT = re.compile(r"^(?P<user>\S+)\s*:\s*(?P<n>\d+) incorrect password attempts?")
_SUDO_NOT_ALLOWED = re.compile(r"^(?P<user>\S+)\s*:\s*(?:user NOT in sudoers|command not allowed)")
_SU_SESSION = re.compile(
    r"session opened for user (?P<target>[^\s(]+)(?:\(uid=\d+\))? by (?P<user>[^\s(]*)"
)
_USER_ADDED = re.compile(r"new user: name=(?P<user>[^,\s]+)")
_GROUP_ADD = re.compile(
    r"(?:add '(?P<user1>[^']+)' to (?:shared )?group '(?P<group1>[^']+)'"
    r"|user (?P<user2>\S+) added by \S+ to group (?P<group2>\S+))"
)


def _port(value: str | None) -> int | None:
    return int(value) if value and value.isdigit() else None


def parse_message(proc: str, msg: str) -> tuple[AuthEventKind, dict[str, str | None]] | None:
    """Classify one syslog message. Returns the event kind and extracted fields."""
    name = proc.lower()
    if name == "sshd":
        for regex, kind in (
            (_FAILED, AuthEventKind.FAILED_LOGIN),
            (_ACCEPTED, AuthEventKind.ACCEPTED_LOGIN),
            (_INVALID, AuthEventKind.INVALID_USER),
            (_CONN, AuthEventKind.CONNECTION),
            (_CONN2, AuthEventKind.CONNECTION),
        ):
            match = regex.match(msg)
            if match:
                return kind, match.groupdict()
    if name == "sudo":
        msg = msg.strip()
        for sudo_regex, sudo_kind in (
            (_SUDO_CMD, AuthEventKind.SUDO_COMMAND),
            (_SUDO_INCORRECT, AuthEventKind.SUDO_INCORRECT_ATTEMPTS),
            (_SUDO_NOT_ALLOWED, AuthEventKind.SUDO_NOT_IN_SUDOERS),
        ):
            match = sudo_regex.match(msg)
            if match:
                return sudo_kind, match.groupdict()
    pam = _PAM.match(msg)
    if pam:
        rest = pam["rest"]
        user = re.search(r"\buser=(\S+)", rest)
        rhost = re.search(r"\brhost=(\S*)", rest)
        kind = AuthEventKind.SUDO_FAILURE if pam["svc"] == "sudo" else AuthEventKind.PAM_FAILURE
        return kind, {
            "user": user.group(1) if user else None,
            "ip": rhost.group(1) if rhost and rhost.group(1) else None,
        }
    if name == "su":
        su = _SU_SESSION.search(msg)
        if su:
            return AuthEventKind.SU_SESSION, su.groupdict()
    added = _USER_ADDED.search(msg)
    if added and name in ("useradd", "adduser"):
        return AuthEventKind.USER_ADDED, added.groupdict()
    group = _GROUP_ADD.search(msg)
    if group:
        return AuthEventKind.GROUP_MEMBER_ADDED, {
            "user": group["user1"] or group["user2"],
            "group": group["group1"] or group["group2"],
        }
    return None


def parse_line(line: str, lineno: int, clock: SyslogClock) -> AuthEvent | None:
    """Parse one auth.log / secure line; ``None`` if irrelevant or unparseable."""
    header = _HEADER_RE.match(line)
    if not header:
        return None
    parsed = parse_message(header["proc"], header["msg"])
    if parsed is None:
        return None
    kind, groups = parsed
    return AuthEvent(
        kind=kind,
        timestamp=clock.resolve(header["ts"]),
        host=header["host"],
        process=header["proc"],
        raw=line,
        lineno=lineno,
        user=groups.get("user"),
        ip=groups.get("ip"),
        port=_port(groups.get("port")),
        auth_method=groups.get("method"),
        command=(groups.get("cmd") or "").strip() or None,
        target_user=groups.get("target"),
        group=groups.get("group"),
    )


def looks_like_auth_log(path: Path, sample: int = 200) -> bool:
    """Sniff: most lines have a syslog header and at least one is an auth event."""
    seen = headers = events = 0
    clock = SyslogClock(2000)
    try:
        for lineno, line, _ in iter_lines(path, 4096):
            if not line.strip():
                continue
            seen += 1
            if _HEADER_RE.match(line):
                headers += 1
                events += parse_line(line, lineno, clock) is not None
            if seen >= sample:
                break
    except BreachHoundError:
        return False
    return seen > 0 and headers * 2 >= seen and events > 0
