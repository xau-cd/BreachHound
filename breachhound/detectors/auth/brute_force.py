"""Brute-force detection on failed authentications (configurable time window)."""

from __future__ import annotations

from datetime import datetime

from breachhound.core.enums import Category, Severity, SourceType
from breachhound.core.models import Finding, stable_id
from breachhound.detectors.auth.parser import AuthEvent, AuthEventKind
from breachhound.engine.evidence import build_evidence
from breachhound.utils.windows import Burst, BurstTracker


class BruteForceDetector:
    """Counts failed logins per source IP in a sliding window.

    A burst starts when ``threshold`` failures fall within ``window_seconds`` (inclusive)
    and ends when no failure is seen for a full window.
    """

    def __init__(self, threshold: int, window_seconds: int) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds
        self._tracker = BurstTracker(threshold, window_seconds)
        self.total_failures: dict[str, int] = {}

    def observe(self, event: AuthEvent) -> None:
        if event.kind is not AuthEventKind.FAILED_LOGIN or not event.ip:
            return
        self.total_failures[event.ip] = self.total_failures.get(event.ip, 0) + 1
        if event.timestamp is not None:
            self._tracker.add(event.ip, event.timestamp, event.lineno, event.user, event.raw)

    def latest(self, ip: str) -> Burst | None:
        return self._tracker.latest(ip)

    def finish(self) -> list[Burst]:
        return self._tracker.finish()

    def finding_for(self, burst: Burst, source: str) -> Finding:
        users = sorted(burst.users)
        attack = "password_spraying" if len(users) >= 3 else "brute_force"
        title = (
            "Password spraying against multiple accounts"
            if attack == "password_spraying"
            else "SSH brute-force attack"
        )
        severity = Severity.HIGH if burst.count >= 10 * self.threshold else Severity.MEDIUM
        confidence = min(0.95, 0.70 + 0.02 * (burst.count - self.threshold))
        return Finding(
            id=stable_id("F", "AUTH-BRUTE", source, burst.first_line, burst.key),
            category=Category.BRUTE_FORCE,
            severity=severity,
            title=title,
            source=SourceType.AUTH,
            confidence=confidence,
            timestamp=burst.start,
            source_file=source,
            source_line=burst.first_line,
            ip=burst.key,
            description=(
                f"{burst.count} failed logins from {burst.key} between "
                f"{_fmt(burst.start)} and {_fmt(burst.end)} "
                f"(threshold {self.threshold} within {self.window_seconds}s)."
            ),
            evidence=[build_evidence(source, ln, raw) for ln, raw in burst.samples[:3]],
            rule_id="AUTH-BRUTE-FORCE",
            metadata={
                "event_count": burst.count,
                "failure_count": burst.count,
                "distinct_users": len(users),
                "usernames": users[:10],
                "attack_type": attack,
                "window_seconds": self.window_seconds,
                "threshold": self.threshold,
                "first_seen": burst.start.isoformat(),
                "last_seen": burst.end.isoformat(),
            },
        )


def _fmt(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S UTC")
