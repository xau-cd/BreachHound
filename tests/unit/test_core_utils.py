from __future__ import annotations

import gzip
import json
import logging

from breachhound.config.settings import Settings, load_settings, update_env_file
from breachhound.config.validator import ensure_valid, validate_settings
from breachhound.core.exceptions import ConfigError, FileAccessError
from breachhound.core.models import Evidence, Finding, to_jsonable
from breachhound.core.enums import Category, Severity, SourceType
from breachhound.engine.evidence import sanitize_excerpt
from breachhound.utils.filesystem import iter_lines
from breachhound.utils.logging import redact_secrets, setup_logging
from breachhound.utils.timestamps import parse_apache_timestamp, parse_iso_timestamp, parse_syslog_timestamp

import pytest


def test_timestamps():
    assert parse_apache_timestamp("10/Oct/2026:13:55:36 -0700").hour == 20
    assert parse_apache_timestamp("31/Feb/2026:00:00:00 +0000") is None
    assert parse_apache_timestamp("garbage") is None
    assert parse_syslog_timestamp("Feb 30 10:00:00", 2026) is None
    assert parse_iso_timestamp("2026-10-12T10:00:00.123456+02:00").hour == 8
    assert parse_iso_timestamp("2026-10-12T10:00:00Z").hour == 10 and parse_iso_timestamp("nope") is None


def test_iter_lines_edge_cases(tmp_path):
    path = tmp_path / "f.log"
    path.write_bytes(b"ok\n" + b"X" * 100 + b"\nlast\xff")
    lines = list(iter_lines(path, 10))
    assert [n for n, _, _ in lines] == [1, 2, 3]
    assert lines[1][2] is True and len(lines[1][1]) == 10 and lines[2][1].startswith("last")
    gz = tmp_path / "f.log.gz"
    with gzip.open(gz, "wb") as fh:
        fh.write(b"a\nb\n")
    assert [t for _, t, _ in iter_lines(gz)] == ["a", "b"]
    with pytest.raises(FileAccessError):
        list(iter_lines(tmp_path / "missing.log"))
    with pytest.raises(FileAccessError):
        list(iter_lines(tmp_path))


def test_settings_roundtrip_and_masking(tmp_path):
    env = tmp_path / ".env"
    update_env_file(env, {"BREACHHOUND_LLM_PROVIDER": "cloud", "BREACHHOUND_CLOUD_API_KEY": "sk-abcdefghijklmnop1234",
                          "BREACHHOUND_CLOUD_PRESET": "anthropic"})
    update_env_file(env, {"BREACHHOUND_LLM_PROVIDER": "ollama"})
    assert env.read_text().count("BREACHHOUND_LLM_PROVIDER") == 1
    assert oct(env.stat().st_mode & 0o777) == "0o600"
    s = load_settings(env, environ={})
    assert s.llm_provider == "ollama" and s.cloud_api_style == "anthropic"
    assert "abcdefghijklmnop" not in repr(s) and "abcdefghijklmnop" not in json.dumps(s.masked())
    assert s.masked()["cloud_api_key"].endswith("1234")


def test_settings_errors(tmp_path):
    with pytest.raises(ConfigError):
        Settings.from_mapping({"BREACHHOUND_LLM_TIMEOUT": "abc"})
    with pytest.raises(ConfigError):
        load_settings(tmp_path / "missing.env", environ={})
    bad = Settings(llm_provider="cloud", cloud_endpoint="ftp://x", cloud_api_key=None)
    assert len([i for i in validate_settings(bad) if i.level == "error"]) >= 2
    with pytest.raises(ConfigError):
        ensure_valid(bad)
    ensure_valid(Settings())


def test_redaction_and_logging():
    text = "Authorization: Bearer abcdefghijklmnop and key sk-ABCDEFGHIJKLMNOPQRST and api_key=supersecret123"
    out = redact_secrets(text)
    assert "abcdefghijklmnop" not in out and "ABCDEFGHIJKLMNOPQRST" not in out and "supersecret123" not in out
    logger = setup_logging(debug=True)
    assert logger.level == logging.DEBUG
    assert sanitize_excerpt("a```b\x00c") == "a'''b?c"
    assert len(sanitize_excerpt("x" * 2000)) < 600


def test_models_serialise():
    f = Finding(id="F-1", category=Category.XSS, severity=Severity.HIGH, title="t", source=SourceType.WEB, confidence=0.8,
                evidence=[Evidence("a.log", 3, "line")])
    data = f.to_dict()
    assert data["category"] == "XSS" and data["confidence_level"] == "HIGH" and data["evidence"][0]["id"].startswith("EV-")
    assert json.dumps(to_jsonable({"s": {1, 2}}))
