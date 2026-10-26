from __future__ import annotations

import json

from click.testing import CliRunner

from breachhound.cli.main import cli
from conftest import EXAMPLE


def invoke(*args):
    return CliRunner().invoke(cli, list(args))


def test_version():
    result = invoke("version")
    assert result.exit_code == 0 and "BreachHound" in result.output


def test_investigate_generates_reports(tmp_path):
    out = tmp_path / "reports"
    result = invoke("investigate", "--target", str(EXAMPLE), "--goal", "Trouver le vecteur", "-o", str(out),
                    "--no-llm", "--reference-time", "2026-10-12T18:00:00Z")
    assert result.exit_code == 0, result.output
    assert "CRITICAL" in result.output and "Traceback" not in result.output
    assert len(list(out.glob("*.md"))) == 1 and len(list(out.glob("*.json"))) == 1
    json.loads(next(out.glob("*.json")).read_text())


def test_missing_target_is_clean_error(tmp_path):
    result = invoke("investigate", "--target", str(tmp_path / "nope"), "--no-llm", "-o", str(tmp_path / "o"))
    assert result.exit_code == 4 and "introuvable" in result.output and "Traceback" not in result.output


def test_output_inside_target_is_refused(example_copy):
    result = invoke("investigate", "--target", str(example_copy), "--no-llm", "-o", str(example_copy / "reports"))
    assert result.exit_code == 3 and "lecture seule" in result.output


def test_fail_on(tmp_path):
    result = invoke("investigate", "--target", str(EXAMPLE), "--no-llm", "-q", "-o", str(tmp_path), "--fail-on", "high")
    assert result.exit_code == 10


def test_bad_reference_time(tmp_path):
    result = invoke("investigate", "--target", str(EXAMPLE), "--no-llm", "-o", str(tmp_path), "--reference-time", "yesterday")
    assert result.exit_code == 3


def test_configure_non_interactive_and_masking(tmp_path):
    env = tmp_path / ".env"
    result = invoke("configure", "--env-file", str(env), "--provider", "cloud", "--preset", "anthropic",
                    "--api-key", "sk-supersecretvalue1234567", "--non-interactive")
    assert result.exit_code == 0, result.output
    assert "supersecretvalue" not in result.output and "****" in result.output
    assert "BREACHHOUND_CLOUD_API_KEY" in env.read_text()
    ollama = invoke("configure", "--env-file", str(env), "--provider", "ollama", "--model", "llama3.1", "--non-interactive")
    assert ollama.exit_code == 0 and "ollama" in env.read_text()


def test_configure_requires_provider_non_interactive(tmp_path):
    result = invoke("configure", "--env-file", str(tmp_path / ".env"), "--non-interactive")
    assert result.exit_code == 3 and "Traceback" not in result.output


def test_doctor_offline(tmp_path):
    env = tmp_path / "doctor.env"
    env.write_text("BREACHHOUND_LLM_PROVIDER=none\n")
    result = invoke("doctor", "--offline", "--env-file", str(env))
    assert result.exit_code == 0 and "doctor" in result.output.lower()
    bad = tmp_path / "bad.env"
    bad.write_text("BREACHHOUND_LLM_PROVIDER=cloud\n")
    assert "ÉCHEC" in invoke("doctor", "--offline", "--env-file", str(bad)).output
