"""Markdown report renderer (Jinja2)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from breachhound.core.exceptions import ReportError
from breachhound.reports.builder import MAX_FINDINGS_IN_MD, MAX_MANIFEST_IN_MD, MAX_TIMELINE_IN_MD

_TEMPLATES = Path(__file__).parent / "templates"
_SEV = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _cell(value: object) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ").replace("\r", " ").replace("<", "&lt;")


def _time(value: object) -> str:
    return str(value)[:19].replace("T", " ") if value else "unknown"


def render_markdown(report: dict[str, Any]) -> str:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES)), autoescape=False, undefined=StrictUndefined,
        trim_blocks=True, lstrip_blocks=True, keep_trailing_newline=True,
    )
    env.filters["cell"] = _cell
    env.filters["time"] = _time
    try:
        findings = sorted(report["findings"], key=lambda f: (-_SEV[f["severity"]], -f["confidence"]))
        return env.get_template("incident.md.j2").render(
            r=report, top_findings=findings[:MAX_FINDINGS_IN_MD], findings_hidden=max(0, len(findings) - MAX_FINDINGS_IN_MD),
            timeline=report["timeline"][:MAX_TIMELINE_IN_MD], timeline_hidden=max(0, len(report["timeline"]) - MAX_TIMELINE_IN_MD),
            manifest=report["evidence"]["artifact_manifest"][:MAX_MANIFEST_IN_MD],
            manifest_hidden=max(0, len(report["evidence"]["artifact_manifest"]) - MAX_MANIFEST_IN_MD),
        )
    except Exception as exc:  # noqa: BLE001 - template errors become business errors
        raise ReportError(f"Échec du rendu Markdown : {exc}") from exc
