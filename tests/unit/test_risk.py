from __future__ import annotations

from datetime import timedelta

from helpers import T0

from breachhound.core.enums import Category, RiskLevel, Severity, SourceType
from breachhound.core.models import Finding
from breachhound.engine.correlator import Correlator
from breachhound.engine.risk import RiskEngine, level_for, repetition_factor


def mk(cat, sev=Severity.HIGH, conf=0.9, offset=0, ip="198.51.100.1", meta=None):
    return Finding(id=f"{cat.value}-{offset}", category=cat, severity=sev, title="t", source=SourceType.WEB,
                   confidence=conf, timestamp=T0 + timedelta(seconds=offset), ip=ip, metadata=meta or {})


def test_empty_is_low():
    risk = RiskEngine().assess([])
    assert risk.score == 0 and risk.level is RiskLevel.LOW and risk.confidence == 0.0


def test_levels():
    assert [level_for(s) for s in (0, 24, 25, 49, 50, 74, 75, 100)] == [
        RiskLevel.LOW, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.MEDIUM,
        RiskLevel.HIGH, RiskLevel.HIGH, RiskLevel.CRITICAL, RiskLevel.CRITICAL]


def test_repetition_is_capped():
    assert repetition_factor(1) == 1.0 and repetition_factor(10**9) == 1.5


def test_single_attempt_is_not_critical():
    risk = RiskEngine().assess([mk(Category.SQL_INJECTION)])
    assert risk.level in (RiskLevel.LOW, RiskLevel.MEDIUM) and risk.score > 0


def test_repetition_increases_score():
    one = RiskEngine().assess([mk(Category.SQL_INJECTION)]).score
    many = RiskEngine().assess([mk(Category.SQL_INJECTION, offset=i) for i in range(20)]).score
    assert many > one


def test_severity_and_confidence_matter():
    low = RiskEngine().assess([mk(Category.SQL_INJECTION, Severity.MEDIUM, 0.5)]).score
    high = RiskEngine().assess([mk(Category.SQL_INJECTION, Severity.HIGH, 0.9)]).score
    assert high > low


def test_webshell_with_post_compromise_is_critical():
    findings = [
        mk(Category.WEBSHELL, Severity.CRITICAL, 0.95, 0, ip=None),
        mk(Category.PRIVILEGE_ESCALATION, Severity.HIGH, 0.7, 60, ip=None),
    ]
    risk = RiskEngine().assess(findings)
    assert risk.level is RiskLevel.CRITICAL and risk.score >= 75
    assert any(f.name == "Web shell" for f in risk.factors)
    assert any(f.name == "Post-compromise activity" for f in risk.factors)


def test_success_after_brute_force_floor_is_high():
    risk = RiskEngine().assess([mk(Category.AUTH_SUCCESS_AFTER_BRUTE_FORCE, Severity.CRITICAL, 0.3)])
    assert risk.level.rank >= RiskLevel.HIGH.rank


def test_correlation_bonus():
    findings = [mk(Category.SQL_INJECTION, Severity.MEDIUM, 0.5, offset=0),
                mk(Category.FILE_UPLOAD, Severity.LOW, 0.4, offset=10)]
    c = Correlator()
    incidents = c.build_incidents(c.correlate(findings))
    assert incidents and len(incidents[0].stages) == 2
    assert RiskEngine().assess(findings, incidents).score > RiskEngine().assess(findings, []).score
