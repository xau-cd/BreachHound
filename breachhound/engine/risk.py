"""Deterministic risk engine, independent of any LLM.

Score (0-100)
-------------
* finding_score = severity_points x confidence x impact
  severity_points: INFO 0, LOW 5, MEDIUM 15, HIGH 30, CRITICAL 50
  impact: RCE/web shell/privilege 1.3, SQLi/successful login 1.2, otherwise 1.0
* Findings are grouped by (category, ip|user). A group scores
  max(finding_score) x repetition, repetition = min(1.5, 1 + 0.1 x log2(events)).
* Group scores are summed, then bonuses are added:
  correlation +10 per extra kill-chain stage in an incident (max +40),
  privileged activity +15, web shell +25 (executable upload only: +10),
  post-compromise activity +20.
* Level: 0-24 LOW, 25-49 MEDIUM, 50-74 HIGH, 75-100 CRITICAL.
  Floors: successful login after brute force or a confident web shell => at least HIGH;
  web shell + post-compromise activity => CRITICAL.
"""

from __future__ import annotations

import math
from collections.abc import Sequence

from breachhound.core.enums import Category, RiskLevel, Severity
from breachhound.core.models import Finding, Incident, RiskAssessment, RiskFactor
from breachhound.engine.timeline import sort_key

SEVERITY_POINTS = {
    Severity.INFO: 0.0,
    Severity.LOW: 5.0,
    Severity.MEDIUM: 15.0,
    Severity.HIGH: 30.0,
    Severity.CRITICAL: 50.0,
}
_C = Category
IMPACT = {
    _C.REMOTE_CODE_EXECUTION: 1.3,
    _C.WEBSHELL: 1.3,
    _C.WEBSHELL_ACCESS: 1.3,
    _C.PRIVILEGE_ESCALATION: 1.3,
    _C.SQL_INJECTION: 1.2,
    _C.AUTH_SUCCESS_AFTER_BRUTE_FORCE: 1.2,
}
_PRIVILEGED = {_C.PRIVILEGE_ESCALATION, _C.ACCOUNT_CHANGE, _C.ROOT_LOGIN}
_COMPROMISE = {_C.WEBSHELL, _C.UPLOAD_EXEC, _C.AUTH_SUCCESS_AFTER_BRUTE_FORCE}
_POST = {_C.PRIVILEGE_ESCALATION, _C.ACCOUNT_CHANGE, _C.WEBSHELL_ACCESS, _C.ROOT_LOGIN}
FORMULA = __doc__ or ""


def finding_score(finding: Finding) -> float:
    return SEVERITY_POINTS[finding.severity] * finding.confidence * IMPACT.get(finding.category, 1.0)


def repetition_factor(events: int) -> float:
    return min(1.5, 1.0 + 0.1 * math.log2(max(events, 1)))


def level_for(score: int) -> RiskLevel:
    if score >= 75:
        return RiskLevel.CRITICAL
    if score >= 50:
        return RiskLevel.HIGH
    if score >= 25:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


class RiskEngine:
    def assess(self, findings: Sequence[Finding], incidents: Sequence[Incident] = ()) -> RiskAssessment:
        if not findings:
            return RiskAssessment(0, RiskLevel.LOW, 0.0, [], FORMULA)
        groups: dict[tuple[str, str], list[Finding]] = {}
        for f in findings:
            groups.setdefault((f.category.value, f.ip or f.user or "n/a"), []).append(f)
        scored = []
        for (cat, key), items in groups.items():
            events = sum(max(1, int(f.metadata.get("event_count", 1))) for f in items)
            points = max(finding_score(f) for f in items) * repetition_factor(events)
            scored.append((points, cat, key, events))
        scored.sort(reverse=True)
        factors = [RiskFactor(f"{c} [{k}]", round(p, 1), f"{n} event(s)") for p, c, k, n in scored[:6] if p > 0]
        total = sum(p for p, *_ in scored)

        def bonus(name: str, points: float, detail: str) -> None:
            nonlocal total
            total += points
            factors.append(RiskFactor(name, points, detail))

        stages = max((len(i.stages) for i in incidents), default=1)
        if stages > 1:
            bonus("Correlation", min(40.0, 10.0 * (stages - 1)), f"{stages} kill-chain stages in one incident")
        cats = {f.category for f in findings}
        if any(f.category in _PRIVILEGED and f.confidence >= 0.5 for f in findings):
            bonus("Privileged activity", 15.0, "sudo/account/root activity")
        shell = any(f.category is _C.WEBSHELL and f.confidence >= 0.6 for f in findings) or any(
            f.category is _C.WEBSHELL_ACCESS and f.metadata.get("outcome") == "possible_success" for f in findings
        )
        if shell:
            bonus("Web shell", 25.0, "web shell present or accessed")
        elif _C.UPLOAD_EXEC in cats:
            bonus("Executable upload", 10.0, "script inside an upload directory")
        post = self._post_compromise(findings)
        if post:
            bonus("Post-compromise activity", 20.0, "privileged/web shell activity after a compromise indicator")
        score = int(round(min(100.0, total)))
        level = level_for(score)
        strong_shell = any(f.category is _C.WEBSHELL and f.confidence >= 0.8 for f in findings)
        floor = None
        if shell and post:
            floor = RiskLevel.CRITICAL
        elif _C.AUTH_SUCCESS_AFTER_BRUTE_FORCE in cats or strong_shell:
            floor = RiskLevel.HIGH
        if floor is not None and level.rank < floor.rank:
            score = 75 if floor is RiskLevel.CRITICAL else 50
            level = floor
            factors.append(RiskFactor("Severity floor", 0.0, f"raised to {floor.value} by compromise indicators"))
        return RiskAssessment(score, level, self._confidence(findings, incidents), factors, FORMULA)

    @staticmethod
    def _post_compromise(findings: Sequence[Finding]) -> bool:
        indicators = [
            f for f in findings if f.category in _COMPROMISE
            or (f.category is _C.REMOTE_CODE_EXECUTION and f.metadata.get("outcome") == "possible_success")
        ]
        stamped = [f for f in indicators if f.timestamp]
        if not stamped:
            return False
        first = min(stamped, key=sort_key)
        return any(
            f.category in _POST and f.timestamp and f.timestamp >= first.timestamp and f.id != first.id  # type: ignore[operator]
            for f in findings
        )

    @staticmethod
    def _confidence(findings: Sequence[Finding], incidents: Sequence[Incident]) -> float:
        top = sorted(findings, key=finding_score, reverse=True)[:5]
        weights = [finding_score(f) for f in top]
        if sum(weights) <= 0:
            return round(max(f.confidence for f in findings), 2)
        conf = sum(f.confidence * w for f, w in zip(top, weights, strict=True)) / sum(weights)
        if any(len(i.stages) > 1 and i.link_reasons.get("same_ip", 0) + i.link_reasons.get("same_file", 0) > 0 for i in incidents):
            conf = min(0.98, conf + 0.05)
        return round(conf, 2)
