from __future__ import annotations

from datetime import timedelta

from helpers import T0

from breachhound.core.enums import Category, Severity, SourceType
from breachhound.core.models import Finding
from breachhound.engine.correlator import Correlator


def mk(fid, cat, sev=Severity.HIGH, *, ip=None, offset=0, user=None, meta=None, conf=0.9, src=SourceType.WEB):
    return Finding(id=fid, category=cat, severity=sev, title=cat.value, source=src, confidence=conf,
                   timestamp=T0 + timedelta(seconds=offset), ip=ip, user=user, metadata=meta or {})


def test_full_attack_chain_is_one_incident():
    findings = [
        mk("f1", Category.SQL_INJECTION, ip="198.51.100.1", offset=0, meta={"request_path": "/p.php"}),
        mk("f2", Category.FILE_UPLOAD, Severity.LOW, ip="198.51.100.1", offset=120),
        mk("f3", Category.WEBSHELL, Severity.CRITICAL, offset=125, src=SourceType.ARTIFACT,
           meta={"relative_path": "webroot/uploads/a.php"}),
        mk("f4", Category.WEBSHELL_ACCESS, ip="198.51.100.1", offset=140, meta={"request_path": "/uploads/a.php"}),
        mk("f5", Category.PRIVILEGE_ESCALATION, offset=300, user="www-data", src=SourceType.AUTH),
    ]
    correlator = Correlator(3600)
    incidents = correlator.build_incidents(correlator.correlate(findings))
    assert len(incidents) == 1
    inc = incidents[0]
    assert set(inc.finding_ids) == {"f1", "f2", "f3", "f4", "f5"}
    assert inc.stages[:2] == ["exploitation", "upload"] and "webshell_persistence" in inc.stages
    assert inc.link_reasons["same_ip"] >= 1 and inc.link_reasons["same_file"] >= 1
    assert inc.severity is Severity.CRITICAL and inc.probable_vector and "198.51.100.1" in inc.probable_vector
    assert all(h.basis == "deterministic-correlation" for h in inc.hypotheses)


def test_unrelated_ips_stay_separate():
    findings = [mk("a", Category.SQL_INJECTION, ip="198.51.100.1"), mk("b", Category.XSS, ip="198.51.100.2", offset=10)]
    groups = Correlator(3600).correlate(findings)
    assert len(groups) == 2


def test_time_window_splits_same_ip():
    findings = [mk("a", Category.SQL_INJECTION, ip="198.51.100.1", offset=0),
                mk("b", Category.SQL_INJECTION, ip="198.51.100.1", offset=7200)]
    assert len(Correlator(3600).correlate(findings)) == 2
    assert len(Correlator(10_000).correlate(findings)) == 1


def test_low_severity_noise_is_not_an_incident():
    findings = [mk("a", Category.SCANNER, Severity.LOW, ip="198.51.100.1")]
    correlator = Correlator()
    assert correlator.build_incidents(correlator.correlate(findings)) == []


def test_weak_links_lower_confidence():
    strong = [mk("a", Category.SQL_INJECTION, ip="198.51.100.1"), mk("b", Category.FILE_UPLOAD, Severity.MEDIUM, ip="198.51.100.1", offset=5)]
    weak = [mk("a", Category.SQL_INJECTION, ip="198.51.100.1"),
            mk("c", Category.UPLOAD_EXEC, offset=30, src=SourceType.ARTIFACT)]
    c = Correlator()
    conf_strong = c.build_incidents(c.correlate(strong))[0].confidence
    inc_weak = c.build_incidents(c.correlate(weak))[0]
    assert inc_weak.link_reasons.get("temporal_proximity") == 1 and inc_weak.confidence < conf_strong


def test_no_compromise_hypothesis_is_explicit():
    findings = [mk("a", Category.SQL_INJECTION, ip="198.51.100.1")]
    c = Correlator()
    inc = c.build_incidents(c.correlate(findings))[0]
    assert "no deterministic indicator" in inc.hypotheses[0].statement
