from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

import pytest

from breachhound.config.settings import Settings
from breachhound.core.enums import Category, RiskLevel
from breachhound.core.exceptions import LLMTimeoutError, ReportError, TargetNotFoundError
from breachhound.engine.investigator import InvestigationOptions, Investigator, STAGES
from breachhound.reports.builder import build_report, write_reports
from helpers import StubProvider

REF = datetime(2026, 10, 12, 18, tzinfo=timezone.utc)
OPTS = InvestigationOptions(use_llm=False, reference_time=REF)


def run(target, provider=None, options=OPTS, progress=None):
    return Investigator(Settings(), provider, progress).investigate(target, "Trouver le vecteur", options)


def test_full_investigation_on_example(example_copy):
    steps = []
    result = run(example_copy, progress=lambda n, i, t: steps.append((n, i, t)))
    cats = {f.category for f in result.findings}
    assert {Category.SQL_INJECTION, Category.WEBSHELL, Category.AUTH_SUCCESS_AFTER_BRUTE_FORCE, Category.UPLOAD_EXEC} <= cats
    assert result.risk.level is RiskLevel.CRITICAL
    web_incident = next(i for i in result.incidents if "198.51.100.23" in i.ips)
    assert {"exploitation", "upload", "webshell_persistence"} <= set(web_incident.stages)
    assert "SQL injection" in web_incident.probable_vector
    assert any(i for i in result.incidents if "203.0.113.77" in i.ips)
    assert len(steps) == len(STAGES) and result.sources and result.artifact_manifest
    assert any("LLM" in lim for lim in result.limitations)


def test_reports_generated(example_copy, tmp_path):
    result = run(example_copy)
    md_path, json_path = write_reports(result, tmp_path / "out")
    data = json.loads(json_path.read_text())
    assert {"executive_summary", "timeline", "findings", "evidence", "root_cause_analysis", "recommendations", "limitations"} <= set(data)
    assert data["executive_summary"]["severity"] == "CRITICAL"
    md = md_path.read_text()
    for heading in ("## Executive Summary", "## Timeline", "## Findings", "## Evidence", "## Root Cause Analysis",
                    "## Recommendations", "## Limitations"):
        assert heading in md
    assert "could not be performed" in md and "198.51.100.23" in md
    ts = [e["timestamp"] for e in data["timeline"] if e["timestamp"]]
    assert ts == sorted(ts)


def test_target_is_never_modified(example_copy):
    def snap():
        return {str(p): (p.stat().st_mtime_ns, hashlib.sha256(p.read_bytes()).hexdigest()) for p in example_copy.rglob("*") if p.is_file()}

    before = snap()
    run(example_copy)
    assert snap() == before


def test_llm_failure_does_not_stop_investigation(example_copy, tmp_path):
    result = run(example_copy, StubProvider(error=LLMTimeoutError("timeout")), InvestigationOptions(use_llm=True, reference_time=REF))
    assert result.llm.status == "failed" and result.findings and result.risk.score > 0
    md = write_reports(result, tmp_path)[0].read_text()
    assert "could not be performed" in md and "timeout" in md


def test_llm_success_is_separated_from_facts(example_copy, tmp_path):
    answer = json.dumps({"summary": "S", "probable_vector": "SQLi", "root_cause_hypotheses": [
        {"hypothesis": "speculation without evidence", "supporting_finding_ids": [], "confidence": "high"}]})
    result = run(example_copy, StubProvider(answer), InvestigationOptions(use_llm=True, reference_time=REF))
    assert result.llm.status == "ok"
    report = build_report(result)
    assert report["root_cause_analysis"]["llm"]["hypotheses"][0]["evidence_status"] == "unsupported"
    md = write_reports(result, tmp_path)[0].read_text()
    assert "UNVERIFIED SPECULATION" in md and "unverified" in md.lower()


def test_edge_targets(tmp_path):
    with pytest.raises(TargetNotFoundError):
        run(tmp_path / "missing")
    empty = tmp_path / "empty"
    empty.mkdir()
    result = run(empty)
    assert result.findings == [] and result.risk.level is RiskLevel.LOW
    assert any("Aucun log" in lim for lim in result.limitations)
    single = tmp_path / "access.log"
    single.write_text('198.51.100.1 - - [12/Oct/2026:10:00:00 +0000] "GET /?a=<script> HTTP/1.1" 200 1 "-" "x"\n')
    assert Category.XSS in {f.category for f in run(single).findings}


def test_report_write_error(example_copy, tmp_path):
    result = run(example_copy)
    blocker = tmp_path / "file"
    blocker.write_text("x")
    with pytest.raises(ReportError):
        write_reports(result, blocker / "sub")
    with pytest.raises(ReportError):
        write_reports(result, tmp_path / "o", ["pdf"])
