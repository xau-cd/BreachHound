"""Authentication analyzer: SSH, sudo, brute-force, bursts, privilege changes."""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import ClassVar

from breachhound.core.constants import PRIVILEGED_GROUPS
from breachhound.core.enums import Category, Severity, SourceType
from breachhound.core.models import Finding, stable_id
from breachhound.detectors.auth.brute_force import BruteForceDetector
from breachhound.detectors.auth.parser import (
    AuthEvent,
    AuthEventKind,
    looks_like_auth_log,
    parse_line,
)
from breachhound.detectors.base import DetectorResult, LogDetector
from breachhound.engine.evidence import build_evidence
from breachhound.utils.filesystem import iter_lines
from breachhound.utils.timestamps import SyslogClock, utc_now
from breachhound.utils.windows import Burst, BurstTracker

_SUSPICIOUS_SUDO = re.compile(
    r"(?:^|[\s/])(?:ba|z|da)?sh(?:\s|$)|\bsu\s+-|chmod\s+[ugoa]*[+=]s|chmod\s+[0-7]*[4-7][0-7]{3}\b"
    r"|\b(?:useradd|adduser|usermod|passwd|chpasswd|visudo|crontab|chattr|setcap)\b"
    r"|/etc/(?:shadow|sudoers|passwd)|\b(?:nc|ncat|netcat|socat)\b|base64\s+-d"
    r"|(?:wget|curl)\b.*\|\s*(?:ba)?sh|/tmp/|/dev/shm/|/var/tmp/"
)
_CONNECTION_KINDS = {
    AuthEventKind.FAILED_LOGIN,
    AuthEventKind.INVALID_USER,
    AuthEventKind.CONNECTION,
}


def _valid_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return None
    return value


class AuthAnalyzer(LogDetector):
    """Detects brute force, success-after-failures, suspicious sudo and account changes."""

    name: ClassVar[str] = "auth"

    def accepts(self, path: Path) -> bool:
        return looks_like_auth_log(path)

    def analyze_file(self, path: Path) -> DetectorResult:
        cfg = self.settings
        result = DetectorResult()
        source = str(path)
        counters: Counter[str] = Counter()
        clock = self._clock(path)
        brute = BruteForceDetector(cfg.brute_force_threshold, cfg.brute_force_window)
        connections = BurstTracker(cfg.connection_burst_threshold, cfg.connection_burst_window)
        horizon = max(cfg.brute_force_window * 6, 1800)

        for lineno, line, _ in iter_lines(path, cfg.max_line_length):
            if lineno > cfg.max_lines:
                result.limitations.append(f"{path}: limite de {cfg.max_lines} lignes atteinte")
                break
            if not line.strip():
                continue
            counters["auth_lines"] += 1
            event = parse_line(line, lineno, clock)
            if event is None:
                counters["auth_unparsed_lines"] += 1
                continue
            counters["auth_events"] += 1
            if event.timestamp is None:
                counters["auth_invalid_timestamps"] += 1
            brute.observe(event)
            if event.kind in _CONNECTION_KINDS and event.ip and event.timestamp is not None:
                connections.add(event.ip, event.timestamp, lineno, event.user, line)
            result.findings.extend(self._handle(event, source, brute, horizon, counters))
            if len(result.findings) >= cfg.max_findings:
                result.limitations.append(f"{path}: limite de {cfg.max_findings} findings atteinte")
                break

        bursts = brute.finish()
        brute_ips = {b.key for b in bursts}
        result.findings.extend(brute.finding_for(b, source) for b in bursts)
        result.findings.extend(self._slow_brute(brute, brute_ips, source))
        for burst in connections.finish():
            if burst.key not in brute_ips:
                result.findings.append(self._connection_burst(burst, source))
        if counters["auth_invalid_timestamps"]:
            result.limitations.append(
                f"{path}: {counters['auth_invalid_timestamps']} événement(s) sans horodatage valide "
                "(non pris en compte dans les fenêtres temporelles)"
            )
        result.limitations.append(
            f"{path}: horodatages syslog sans fuseau interprétés en UTC "
            f"(année {clock.year} déduite : utilisez --year pour la forcer)"
        )
        result.stats.update(counters)
        result.stats["auth_files"] = 1
        return result

    def _clock(self, path: Path) -> SyslogClock:
        if self.settings.syslog_year:
            return SyslogClock(self.settings.syslog_year)
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            mtime = utc_now()
        return SyslogClock(mtime.year, reference=mtime)

    # -- event handlers ---------------------------------------------------------------
    def _handle(
        self,
        event: AuthEvent,
        source: str,
        brute: BruteForceDetector,
        horizon: int,
        counters: Counter[str],
    ) -> list[Finding]:
        kind = event.kind
        if kind is AuthEventKind.ACCEPTED_LOGIN:
            counters["auth_accepted_logins"] += 1
            return self._accepted(event, source, brute, horizon)
        if kind is AuthEventKind.SUDO_COMMAND:
            return self._sudo_command(event, source)
        if kind is AuthEventKind.SUDO_NOT_IN_SUDOERS:
            return [self._make(event, source, Category.PRIVILEGE_ESCALATION, Severity.MEDIUM, 0.75,
                               "sudo attempt by a user not allowed to use sudo", "AUTH-SUDO-DENIED")]
        if kind is AuthEventKind.SUDO_INCORRECT_ATTEMPTS:
            return [self._make(event, source, Category.PRIVILEGE_ESCALATION, Severity.MEDIUM, 0.60,
                               "Repeated incorrect sudo password attempts", "AUTH-SUDO-BADPASS")]
        if kind is AuthEventKind.USER_ADDED:
            return [self._make(event, source, Category.ACCOUNT_CHANGE, Severity.MEDIUM, 0.60,
                               f"New local account created: {event.user}", "AUTH-USER-ADDED")]
        if kind is AuthEventKind.GROUP_MEMBER_ADDED and (event.group or "").lower() in PRIVILEGED_GROUPS:
            return [self._make(event, source, Category.PRIVILEGE_ESCALATION, Severity.HIGH, 0.80,
                               f"Account added to privileged group '{event.group}'", "AUTH-GROUP-PRIV")]
        return []

    def _accepted(
        self, event: AuthEvent, source: str, brute: BruteForceDetector, horizon: int
    ) -> list[Finding]:
        findings: list[Finding] = []
        burst = brute.latest(event.ip) if event.ip else None
        if burst is not None and event.timestamp is not None:
            gap = (event.timestamp - burst.end).total_seconds()
            if 0 <= gap <= horizon:
                finding = self._make(
                    event, source, Category.AUTH_SUCCESS_AFTER_BRUTE_FORCE, Severity.CRITICAL, 0.85,
                    "Successful login after a brute-force burst", "AUTH-SUCCESS-AFTER-BF",
                )
                finding.description = (
                    f"{event.ip} authenticated as '{event.user}' ({event.auth_method}) "
                    f"{int(gap)}s after {burst.count} failed attempts."
                )
                finding.metadata.update({"preceding_failures": burst.count, "gap_seconds": int(gap)})
                finding.evidence.extend(
                    build_evidence(source, ln, raw) for ln, raw in burst.samples[:2]
                )
                findings.append(finding)
        if event.user == "root":
            findings.append(self._make(
                event, source, Category.ROOT_LOGIN, Severity.MEDIUM, 0.60,
                "Direct root login over SSH", "AUTH-ROOT-LOGIN"))
        return findings

    def _sudo_command(self, event: AuthEvent, source: str) -> list[Finding]:
        command = event.command or ""
        if not _SUSPICIOUS_SUDO.search(command):
            return []
        finding = self._make(
            event, source, Category.PRIVILEGE_ESCALATION, Severity.HIGH, 0.70,
            "Suspicious command executed through sudo", "AUTH-SUDO-SUSPICIOUS")
        finding.description = f"{event.user} ran as {event.target_user}: {command[:200]}"
        finding.metadata["command"] = command[:300]
        return [finding]

    def _slow_brute(self, brute: BruteForceDetector, burst_ips: set[str], source: str) -> list[Finding]:
        findings = []
        for ip, total in sorted(brute.total_failures.items()):
            if total >= self.settings.slow_brute_force_total and ip not in burst_ips:
                findings.append(Finding(
                    id=stable_id("F", "AUTH-SLOW-BF", source, ip),
                    category=Category.BRUTE_FORCE,
                    severity=Severity.LOW,
                    title="Repeated authentication failures (low-and-slow)",
                    source=SourceType.AUTH,
                    confidence=0.50,
                    source_file=source,
                    ip=ip,
                    description=f"{total} failed logins from {ip} spread over time, below the burst threshold.",
                    rule_id="AUTH-SLOW-BRUTE-FORCE",
                    metadata={"event_count": total, "failure_count": total},
                ))
        return findings

    def _connection_burst(self, burst: Burst, source: str) -> Finding:
        cfg = self.settings
        return Finding(
            id=stable_id("F", "AUTH-CONN-BURST", source, burst.first_line, burst.key),
            category=Category.CONNECTION_BURST,
            severity=Severity.MEDIUM,
            title="Burst of SSH connections",
            source=SourceType.AUTH,
            confidence=0.60,
            timestamp=burst.start,
            source_file=source,
            source_line=burst.first_line,
            ip=burst.key,
            description=f"{burst.count} connection events from {burst.key} within {cfg.connection_burst_window}s.",
            evidence=[build_evidence(source, ln, raw) for ln, raw in burst.samples[:3]],
            rule_id="AUTH-CONNECTION-BURST",
            metadata={"event_count": burst.count, "window_seconds": cfg.connection_burst_window},
        )

    def _make(
        self,
        event: AuthEvent,
        source: str,
        category: Category,
        severity: Severity,
        confidence: float,
        title: str,
        rule_id: str,
    ) -> Finding:
        return Finding(
            id=stable_id("F", rule_id, source, event.lineno),
            category=category,
            severity=severity,
            title=title,
            source=SourceType.AUTH,
            confidence=confidence,
            timestamp=event.timestamp,
            source_file=source,
            source_line=event.lineno,
            ip=_valid_ip(event.ip),
            user=event.user,
            description=title,
            evidence=[build_evidence(source, event.lineno, event.raw)],
            rule_id=rule_id,
            metadata={"event_count": 1, "process": event.process, "host": event.host},
        )
