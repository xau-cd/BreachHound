"""Assemble the report data model and write Markdown/JSON files."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from breachhound.core.enums import Category, Severity
from breachhound.core.exceptions import ReportError
from breachhound.core.models import Finding, InvestigationResult
from breachhound.engine.risk import FORMULA
from breachhound.utils.filesystem import ensure_dir

MAX_FINDINGS_IN_MD = 200
MAX_TIMELINE_IN_MD = 300
MAX_MANIFEST_IN_MD = 50

RECOMMENDATIONS: dict[Category, list[str]] = {
    Category.SQL_INJECTION: [
        "Use parameterised queries/ORM on every endpoint listed in the findings; validate input server-side.",
        "Review database logs for the attack window and rotate database credentials if any attempt may have succeeded.",
    ],
    Category.XSS: ["Apply contextual output encoding and a restrictive Content-Security-Policy."],
    Category.PATH_TRAVERSAL: ["Canonicalise and whitelist file paths; run the web server with least privilege and chroot/containers."],
    Category.REMOTE_CODE_EXECUTION: [
        "Patch or disable the vulnerable component, and block shell metacharacters at the WAF as a stop-gap.",
        "Assume code execution as the web user for any request flagged 'possible_success'; hunt for persistence.",
    ],
    Category.WEBSHELL: [
        "Isolate the host, preserve a forensic copy (disk image + hashes), then remove the web shell from a clean state.",
        "Rotate every secret readable by the web server user (DB passwords, API keys, session keys).",
    ],
    Category.WEBSHELL_ACCESS: ["Block the attacker IP(s) and review all requests to the script path for command output exfiltration."],
    Category.UPLOAD_EXEC: ["Disable script execution in upload directories (server config) and store uploads outside the web root."],
    Category.FILE_UPLOAD: ["Validate upload type by content, rename files, restrict extensions and permissions."],
    Category.BRUTE_FORCE: ["Enforce key-based SSH, disable password authentication, deploy fail2ban/rate limiting and MFA."],
    Category.AUTH_SUCCESS_AFTER_BRUTE_FORCE: [
        "Treat the successful account as compromised: disable it, kill sessions, rotate credentials and review its shell history.",
    ],
    Category.PRIVILEGE_ESCALATION: ["Audit sudoers and privileged groups; review commands run through sudo during the incident window."],
    Category.ACCOUNT_CHANGE: ["Remove unauthorised accounts and review /etc/passwd, /etc/group, authorized_keys and cron entries."],
    Category.ROOT_LOGIN: ["Disable direct root login over SSH (PermitRootLogin no)."],
    Category.INTEGRITY: ["Restore modified files from a trusted source and compare against the baseline."],
    Category.EXTENSION_MISMATCH: ["Quarantine files whose content does not match their extension and inspect them offline."],
    Category.SCANNER: ["Rate-limit or block scanning sources; keep WAF/IDS signatures up to date."],
    Category.RECON: ["Remove exposed configuration/backup files and restrict access to administrative paths."],
}
GENERAL_RECOMMENDATIONS = [
    "Preserve evidence first: keep read-only copies of the analysed logs and files with the SHA-256 listed in this report.",
    "Extend the investigation to other hosts contacted by the IP address(es) listed above.",
]


def _counts(findings: Iterable[Finding]) -> dict[str, int]:
    counter = Counter(f.severity.value for f in findings)
    return {s.value: counter.get(s.value, 0) for s in reversed(list(Severity))}


def _facts(result: InvestigationResult) -> list[str]:
    facts: list[str] = []
    by_cat: dict[str, list[Finding]] = {}
    for f in result.findings:
        by_cat.setdefault(f.category.value, []).append(f)
    for cat, items in sorted(by_cat.items(), key=lambda kv: -max(f.severity.rank for f in kv[1])):
        ips = sorted({f.ip for f in items if f.ip})
        stamps = sorted(f.timestamp for f in items if f.timestamp)
        span = f" between {stamps[0]:%Y-%m-%d %H:%M:%S} and {stamps[-1]:%H:%M:%S} UTC" if stamps else ""
        events = sum(int(f.metadata.get("event_count", 1)) for f in items)
        facts.append(f"{cat}: {len(items)} finding(s), {events} event(s){span}" + (f"; IP(s): {', '.join(ips[:5])}" if ips else ""))
    return facts


def _recommendations(result: InvestigationResult) -> list[dict[str, str]]:
    seen: set[str] = set()
    out: list[dict[str, str]] = []
    cats = sorted({f.category for f in result.findings}, key=lambda c: -max(f.severity.rank for f in result.findings if f.category is c))
    for cat in cats:
        for text in RECOMMENDATIONS.get(cat, []):
            if text not in seen:
                seen.add(text)
                out.append({"text": text, "origin": f"deterministic ({cat.value})"})
    for text in result.llm.recommendations:
        if text not in seen:
            seen.add(text)
            out.append({"text": text, "origin": "LLM suggestion (to be validated)"})
    out.extend({"text": t, "origin": "general"} for t in GENERAL_RECOMMENDATIONS)
    return out


def build_report(result: InvestigationResult) -> dict[str, Any]:
    """Build the full report dictionary (single source for Markdown and JSON)."""
    risk = result.risk
    assert risk is not None, "risk must be computed before building a report"
    top = result.incidents[0] if result.incidents else None
    vector = (top.probable_vector if top else None) or "undetermined"
    if result.llm.status == "ok" and result.llm.probable_vector:
        vector_llm = result.llm.probable_vector
    else:
        vector_llm = None
    if top:
        summary = f"{top.summary} Risk {risk.level.value} ({risk.score}/100)."
    elif result.findings:
        summary = f"{len(result.findings)} finding(s) without a correlated incident. Risk {risk.level.value} ({risk.score}/100)."
    else:
        summary = "No finding was produced by the deterministic detectors."
    findings = [f.to_dict() for f in result.findings]
    return {
        "metadata": {
            "id": result.id, "tool": "BreachHound", "tool_version": result.tool_version,
            "started_at": result.started_at.isoformat(), "finished_at": result.finished_at.isoformat(),
            "duration_seconds": round((result.finished_at - result.started_at).total_seconds(), 2),
            "target": result.target, "goal": result.goal,
        },
        "executive_summary": {
            "severity": risk.level.value, "score": risk.score, "confidence": risk.confidence,
            "confidence_level": risk.confidence_level, "probable_vector": vector,
            "probable_vector_llm_unverified": vector_llm,
            "ips": result.ips, "summary": summary, "severity_counts": _counts(result.findings),
            "findings_total": len(result.findings), "incidents_total": len(result.incidents),
            "llm_status": result.llm.status,
        },
        "risk": risk.to_dict() | {"formula": FORMULA.strip()},
        "timeline": [e.to_dict() for e in result.timeline],
        "findings": findings,
        "incidents": [i.to_dict() for i in result.incidents],
        "evidence": {
            "sources": [s.to_dict() for s in result.sources],
            "artifact_manifest": result.artifact_manifest,
        },
        "root_cause_analysis": {
            "observed_facts": _facts(result),
            "deterministic_hypotheses": [h.to_dict() for i in result.incidents for h in i.hypotheses],
            "llm": {
                "status": result.llm.status, "provider": result.llm.provider, "model": result.llm.model,
                "error": result.llm.error, "summary": result.llm.summary,
                "hypotheses": [h.to_dict() for h in result.llm.hypotheses], "gaps": result.llm.gaps,
            },
        },
        "recommendations": _recommendations(result),
        "limitations": result.limitations,
        "stats": result.stats,
    }


def write_reports(result: InvestigationResult, out_dir: Path, formats: Iterable[str] = ("md", "json")) -> list[Path]:
    """Write the requested report formats and return the created paths."""
    from breachhound.reports.json import render_json
    from breachhound.reports.markdown import render_markdown

    report = build_report(result)
    stamp = result.started_at.strftime("%Y%m%dT%H%M%SZ")
    stem = f"breachhound_{stamp}_{result.id.split('-')[-1]}"
    try:
        ensure_dir(out_dir)
        paths: list[Path] = []
        for fmt in dict.fromkeys(formats):
            path = out_dir / f"{stem}.{fmt}"
            if fmt == "md":
                path.write_text(render_markdown(report), encoding="utf-8")
            elif fmt == "json":
                path.write_text(render_json(report), encoding="utf-8")
            else:
                raise ReportError(f"Format de rapport inconnu : {fmt}")
            paths.append(path)
    except OSError as exc:
        raise ReportError(f"Impossible d'écrire le rapport dans {out_dir} : {exc.strerror or exc}") from exc
    return paths
