"""Web log analyzer (Nginx/Apache Common & Combined formats)."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import ClassVar

from breachhound.core.constants import EXECUTABLE_EXTENSIONS
from breachhound.core.enums import Category, Severity, SourceType
from breachhound.core.models import Finding, stable_id
from breachhound.detectors.base import DetectorResult, LogDetector
from breachhound.detectors.web.parser import (
    WebLogEntry,
    looks_like_web_log,
    parse_line,
    salvage_line,
)
from breachhound.detectors.web.patterns import RuleMatch, normalize_payload, scan_entry
from breachhound.engine.evidence import build_evidence
from breachhound.utils.filesystem import iter_lines
from breachhound.utils.windows import Burst, BurstTracker

_UPLOAD_PATH_RE = re.compile(r"upload|import|attach|file-manager|media/add", re.IGNORECASE)


def _outcome(status: int | None) -> str:
    """Coarse HTTP outcome. A 2xx is *not* proof of success."""
    if status is None:
        return "unknown"
    if 200 <= status < 300:
        return "possible_success"
    if 300 <= status < 400:
        return "redirected"
    if status >= 500:
        return "server_error"
    return "rejected"


def request_path(target: str) -> str:
    """Decoded path portion of a request target (used for cross-source correlation)."""
    path = normalize_payload(target.split("?", 1)[0]).decoded
    return path.split("#", 1)[0]


class WebAnalyzer(LogDetector):
    """Signature-based web attack detector with streaming I/O."""

    name: ClassVar[str] = "web"

    def accepts(self, path: Path) -> bool:
        return looks_like_web_log(path)

    def analyze_file(self, path: Path) -> DetectorResult:
        cfg = self.settings
        result = DetectorResult()
        counters: Counter[str] = Counter()
        tracker = BurstTracker(cfg.web_error_burst_threshold, cfg.web_error_burst_window)
        source = str(path)
        capped = False
        for lineno, line, truncated in iter_lines(path, cfg.max_line_length):
            if lineno > cfg.max_lines:
                result.limitations.append(
                    f"{path}: limite de {cfg.max_lines} lignes atteinte, fichier partiellement analysé"
                )
                break
            if not line.strip():
                continue
            counters["web_lines"] += 1
            counters["web_truncated_lines"] += int(truncated)
            entry = parse_line(line, lineno)
            if entry is not None:
                counters["web_parsed_lines"] += 1
            else:
                entry = salvage_line(line, lineno)
                if entry is None:
                    counters["web_malformed_lines"] += 1
                    continue
                counters["web_salvaged_lines"] += 1
            if entry.timestamp is None:
                counters["web_invalid_timestamps"] += 1
            if len(result.findings) >= cfg.max_findings:
                capped = True
                break
            result.findings.extend(self._scan(entry, source, truncated))
            self._track_errors(entry, tracker)
        for burst in tracker.finish():
            result.findings.append(self._burst_finding(burst, source))
        if capped:
            result.limitations.append(
                f"{path}: limite de {cfg.max_findings} findings atteinte, analyse interrompue"
            )
        if counters["web_malformed_lines"] or counters["web_salvaged_lines"]:
            result.limitations.append(
                f"{path}: {counters['web_malformed_lines']} ligne(s) illisible(s) ignorée(s), "
                f"{counters['web_salvaged_lines']} ligne(s) mal formée(s) analysée(s) en mode brut"
            )
        if counters["web_truncated_lines"]:
            result.limitations.append(
                f"{path}: {counters['web_truncated_lines']} ligne(s) tronquée(s) à "
                f"{cfg.max_line_length} octets"
            )
        if counters["web_invalid_timestamps"]:
            result.limitations.append(
                f"{path}: {counters['web_invalid_timestamps']} horodatage(s) invalide(s) : "
                "chronologie approximative pour ces lignes"
            )
        result.stats.update(counters)
        result.stats["web_files"] = 1
        return result

    # -- internals -----------------------------------------------------------------
    def _scan(self, entry: WebLogEntry, source: str, truncated: bool) -> list[Finding]:
        findings: list[Finding] = []
        by_category: dict[Category, list[RuleMatch]] = {}
        for match in scan_entry(entry):
            by_category.setdefault(match.rule.category, []).append(match)
        for category, group in by_category.items():
            findings.append(self._finding(entry, source, category, group, truncated))
        upload = self._upload_finding(entry, source)
        if upload is not None:
            findings.append(upload)
        return findings

    def _base_meta(self, entry: WebLogEntry, truncated: bool) -> dict[str, object]:
        return {
            "http_method": entry.method,
            "http_status": entry.status,
            "outcome": _outcome(entry.status),
            "request_path": request_path(entry.target),
            "target": entry.target[:300],
            "user_agent": (entry.user_agent or "")[:200],
            "parse_quality": entry.parse_quality,
            "line_truncated": truncated,
            "event_count": 1,
        }

    def _finding(
        self,
        entry: WebLogEntry,
        source: str,
        category: Category,
        group: list[RuleMatch],
        truncated: bool,
    ) -> Finding:
        primary = max(group, key=lambda m: (m.rule.severity.rank, m.rule.confidence))
        rule_ids = sorted({m.rule.id for m in group})
        confidence = min(0.97, primary.rule.confidence + 0.04 * (len(rule_ids) - 1))
        meta = self._base_meta(entry, truncated)
        meta.update(
            {
                "matched_rules": rule_ids,
                "matched_field": primary.field,
                "matched_text": primary.snippet,
                "decode_layers": max(m.layers for m in group),
                "obfuscation_suspected": max(m.layers for m in group) >= 2,
            }
        )
        return Finding(
            id=stable_id("F", primary.rule.id, source, entry.lineno, category.value),
            category=category,
            severity=primary.rule.severity,
            title=primary.rule.title,
            source=SourceType.WEB,
            confidence=confidence,
            timestamp=entry.timestamp,
            source_file=source,
            source_line=entry.lineno,
            ip=entry.ip,
            user=entry.ident_user,
            description=(
                f"{entry.method or '?'} request matched {', '.join(rule_ids)} "
                f"(HTTP {entry.status if entry.status is not None else '?'})."
            ),
            evidence=[build_evidence(source, entry.lineno, entry.raw)],
            rule_id=primary.rule.id,
            metadata=meta,
        )

    def _upload_finding(self, entry: WebLogEntry, source: str) -> Finding | None:
        method = (entry.method or "").upper()
        if method not in ("POST", "PUT"):
            return None
        path = request_path(entry.target)
        ext = Path(path).suffix.lower()
        ok_status = entry.status is not None and entry.status < 400
        if method == "PUT" and ext in EXECUTABLE_EXTENSIONS:
            severity, conf, title, rule = Severity.MEDIUM, 0.70, "HTTP PUT of an executable script", "WEB-PUT-SCRIPT"
        elif ok_status and _UPLOAD_PATH_RE.search(path):
            severity, conf, title, rule = Severity.LOW, 0.40, "File upload request", "WEB-UPLOAD-POST"
        else:
            return None
        meta = self._base_meta(entry, False)
        return Finding(
            id=stable_id("F", rule, source, entry.lineno, Category.FILE_UPLOAD.value),
            category=Category.FILE_UPLOAD,
            severity=severity,
            title=title,
            source=SourceType.WEB,
            confidence=conf,
            timestamp=entry.timestamp,
            source_file=source,
            source_line=entry.lineno,
            ip=entry.ip,
            user=entry.ident_user,
            description=f"{method} {path} -> HTTP {entry.status}. Content cannot be inspected from an access log.",
            evidence=[build_evidence(source, entry.lineno, entry.raw)],
            rule_id=rule,
            metadata=meta,
        )

    def _track_errors(self, entry: WebLogEntry, tracker: BurstTracker) -> None:
        if entry.timestamp is not None and entry.status in (400, 401, 403, 404):
            tracker.add(entry.ip, entry.timestamp, entry.lineno, raw=entry.raw)

    def _burst_finding(self, burst: Burst, source: str) -> Finding:
        cfg = self.settings
        return Finding(
            id=stable_id("F", "WEB-4XX-BURST", source, burst.first_line, burst.key),
            category=Category.RECON,
            severity=Severity.MEDIUM,
            title="High rate of HTTP 4xx responses (scan/enumeration)",
            source=SourceType.WEB,
            confidence=0.60,
            timestamp=burst.start,
            source_file=source,
            source_line=burst.first_line,
            ip=burst.key,
            description=(
                f"{burst.count} client-error responses for one IP within "
                f"{cfg.web_error_burst_window}s (threshold {cfg.web_error_burst_threshold})."
            ),
            evidence=[build_evidence(source, ln, raw) for ln, raw in burst.samples[:3]],
            rule_id="WEB-4XX-BURST",
            metadata={
                "event_count": burst.count,
                "first_seen": burst.start.isoformat(),
                "last_seen": burst.end.isoformat(),
                "window_seconds": cfg.web_error_burst_window,
            },
        )
