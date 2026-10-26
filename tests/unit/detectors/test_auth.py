from __future__ import annotations

from pathlib import Path

from helpers import T0, auth_line, failed, write_lines

from breachhound.core.enums import Category, Severity
from breachhound.detectors.auth.analyzer import AuthAnalyzer
from breachhound.detectors.auth.parser import AuthEventKind, looks_like_auth_log, parse_line
from breachhound.utils.timestamps import SyslogClock
from breachhound.utils.windows import BurstTracker

CLOCK = SyslogClock(2026)


def analyze(tmp_path: Path, settings, lines: list[str]):
    return AuthAnalyzer(settings).analyze_file(write_lines(tmp_path / "auth.log", lines))


def cats(result) -> list[Category]:
    return [f.category for f in result.findings]


def test_parser_variants():
    ev = parse_line(auth_line("Failed password for invalid user admin from 203.0.113.5 port 22 ssh2"), 1, CLOCK)
    assert ev and ev.kind is AuthEventKind.FAILED_LOGIN and ev.user == "admin" and ev.ip == "203.0.113.5"
    ev = parse_line(auth_line("Accepted publickey for alice from 192.0.2.7 port 5 ssh2"), 2, CLOCK)
    assert ev and ev.kind is AuthEventKind.ACCEPTED_LOGIN and ev.auth_method == "publickey"
    ev = parse_line(auth_line("alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls -l", proc="sudo"), 3, CLOCK)
    assert ev and ev.kind is AuthEventKind.SUDO_COMMAND and ev.command == "/bin/ls -l" and ev.target_user == "root"
    assert parse_line("not a syslog line", 4, CLOCK) is None
    assert parse_line(auth_line("CRON something", proc="CRON"), 5, CLOCK) is None


def test_brute_force_threshold_and_window(tmp_path, settings):
    settings.brute_force_threshold, settings.brute_force_window = 5, 60
    burst = [failed("203.0.113.5", offset=i * 5) for i in range(8)]
    result = analyze(tmp_path, settings, burst)
    bf = [f for f in result.findings if f.category is Category.BRUTE_FORCE]
    assert len(bf) == 1 and bf[0].metadata["failure_count"] == 8 and bf[0].ip == "203.0.113.5"
    slow = [failed("203.0.113.6", offset=i * 100) for i in range(8)]  # never 5 within 60s
    assert Category.BRUTE_FORCE not in cats(analyze(tmp_path, settings, slow))


def test_window_is_configurable(tmp_path, settings):
    lines = [failed("203.0.113.5", offset=i * 100) for i in range(5)]
    settings.brute_force_threshold, settings.brute_force_window = 5, 60
    assert Category.BRUTE_FORCE not in cats(analyze(tmp_path, settings, lines))
    settings.brute_force_window = 500
    assert Category.BRUTE_FORCE in cats(analyze(tmp_path, settings, lines))


def test_normal_authentication_produces_nothing(tmp_path, settings):
    lines = [auth_line("Accepted publickey for alice from 192.0.2.7 port 5 ssh2"),
             failed("192.0.2.7", "alice", offset=30),
             auth_line("Accepted password for alice from 192.0.2.7 port 6 ssh2", offset=40)]
    assert analyze(tmp_path, settings, lines).findings == []


def test_multiple_ips_are_separate(tmp_path, settings):
    lines = [failed("203.0.113.5", offset=i) for i in range(6)] + [failed("203.0.113.9", offset=i) for i in range(6)]
    found = {f.ip for f in analyze(tmp_path, settings, lines).findings if f.category is Category.BRUTE_FORCE}
    assert found == {"203.0.113.5", "203.0.113.9"}


def test_success_after_brute_force(tmp_path, settings):
    lines = [failed("203.0.113.5", "root", offset=i) for i in range(6)]
    lines.append(auth_line("Accepted password for deploy from 203.0.113.5 port 9 ssh2", offset=30))
    result = analyze(tmp_path, settings, lines)
    hit = [f for f in result.findings if f.category is Category.AUTH_SUCCESS_AFTER_BRUTE_FORCE]
    assert len(hit) == 1 and hit[0].severity is Severity.CRITICAL and hit[0].metadata["preceding_failures"] == 6


def test_sudo_findings(tmp_path, settings):
    lines = [
        auth_line("alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update", proc="sudo"),
        auth_line("www-data : TTY=unknown ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash -c id", proc="sudo", offset=5),
        auth_line("bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/su", proc="sudo", offset=9),
        auth_line("add 'eve' to group 'sudo'", proc="usermod", offset=12),
        auth_line("new user: name=svc, UID=1002, GID=1002, home=/home/svc, shell=/bin/bash", proc="useradd", offset=14),
    ]
    result = analyze(tmp_path, settings, lines)
    titles = [f.title for f in result.findings]
    assert sum(c is Category.PRIVILEGE_ESCALATION for c in cats(result)) == 3
    assert Category.ACCOUNT_CHANGE in cats(result)
    assert not any("apt update" in f.description for f in result.findings), titles


def test_root_login_and_connection_burst(tmp_path, settings):
    settings.connection_burst_threshold = 10
    lines = [auth_line("Accepted publickey for root from 192.0.2.8 port 1 ssh2")]
    lines += [auth_line(f"Connection closed by 203.0.113.50 port {2000 + i} [preauth]", offset=i) for i in range(12)]
    got = cats(analyze(tmp_path, settings, lines))
    assert Category.ROOT_LOGIN in got and Category.CONNECTION_BURST in got


def test_year_rollover():
    clock = SyslogClock(2026)
    dec = clock.resolve("Dec 31 23:59:59")
    jan = clock.resolve("Jan  1 00:00:05")
    assert dec and jan and (jan - dec).total_seconds() == 6


def test_burst_tracker_bounds():
    tracker = BurstTracker(3, 10)
    for i in range(5):
        tracker.add("a", T0.replace(second=i), i)
    tracker.add("a", T0.replace(minute=30), 99)
    bursts = tracker.finish()
    assert len(bursts) == 1 and bursts[0].count == 5


def test_sniff_and_empty(tmp_path, settings, fixtures_dir):
    assert looks_like_auth_log(fixtures_dir / "ssh" / "auth.log")
    empty = tmp_path / "e.log"
    empty.write_text("")
    assert not looks_like_auth_log(empty) and AuthAnalyzer(settings).analyze_file(empty).findings == []


def test_fixture_file(settings, fixtures_dir):
    result = AuthAnalyzer(settings).analyze_file(fixtures_dir / "ssh" / "auth.log")
    assert Category.AUTH_SUCCESS_AFTER_BRUTE_FORCE in cats(result)
