"""Artifact checker: read-only inspection of a directory tree (never executes anything)."""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, ClassVar

from breachhound.config.settings import Settings
from breachhound.core.constants import (
    BENIGN_HIDDEN_DIRS,
    BENIGN_HIDDEN_NAMES,
    DATA_EXTENSIONS,
    EXECUTABLE_EXTENSIONS,
    SCRIPT_EXTENSIONS,
    UPLOAD_DIR_NAMES,
)
from breachhound.core.enums import Category, Severity, SourceType
from breachhound.core.exceptions import TargetNotFoundError
from breachhound.core.models import Evidence, Finding, stable_id
from breachhound.detectors.artifacts.integrity import diff_manifests, load_baseline
from breachhound.detectors.artifacts.webshell import scan_file
from breachhound.detectors.base import Detector, DetectorResult
from breachhound.engine.evidence import sanitize_excerpt
from breachhound.utils.filesystem import read_head, walk_files
from breachhound.utils.hashing import sha256_file
from breachhound.utils.timestamps import utc_now

_DOUBLE_EXT = re.compile(
    r"\.(?:php\d?|phtml|phar|jsp|jspx|asp|aspx)\.(?:jpe?g|png|gif|bmp|txt|pdf|ico|webp|csv)$"
    r"|\.(?:jpe?g|png|gif|pdf|txt)\.(?:php\d?|phtml|phar|jsp|asp|aspx)$",
    re.IGNORECASE,
)
_SCRIPT_MARKERS = re.compile(rb"<\?(?:php|=)|<%@?\s*(?:page|language|import)|<%\s*(?:eval|execute|response|request)", re.IGNORECASE)
_SERVER_CONFIG_NAMES = {".htaccess", ".user.ini", "web.config"}


class ArtifactChecker(Detector):
    """Finds web shells, executables in upload dirs, mismatches, integrity changes."""

    name: ClassVar[str] = "artifacts"

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        log_files: Iterable[Path] = (),
        baseline: Path | None = None,
        ioc_hashes: Iterable[str] = (),
        reference_time: datetime | None = None,
    ) -> None:
        super().__init__(settings)
        self._log_files = {os.path.abspath(p) for p in log_files}
        self._baseline = baseline
        self._ioc = {h.strip().lower() for h in ioc_hashes if h.strip()}
        self._now = reference_time or utc_now()
        self.manifest: list[dict[str, Any]] = []

    def analyze(self, target: Path) -> DetectorResult:
        if not target.exists() and not target.is_symlink():
            raise TargetNotFoundError(f"Cible introuvable : {target}")
        result = DetectorResult()
        errors: list[str] = []
        self.manifest = []
        files = [target] if target.is_file() else walk_files(target, self.settings.max_files, errors)
        root = target if target.is_dir() else target.parent
        for path in files:
            result.stats["artifact_files_scanned"] = result.stats.get("artifact_files_scanned", 0) + 1
            try:
                result.findings.extend(self._inspect(path, root, result))
            except PermissionError:
                result.limitations.append(f"Permission refusée, fichier non analysé : {path}")
                result.stats["artifact_unreadable_files"] = result.stats.get("artifact_unreadable_files", 0) + 1
            except OSError as exc:
                result.limitations.append(f"Fichier illisible ({exc.strerror or exc}) : {path}")
                result.stats["artifact_unreadable_files"] = result.stats.get("artifact_unreadable_files", 0) + 1
        result.limitations.extend(errors)
        if self._baseline is not None:
            result.findings.extend(self._integrity_findings(root))
        else:
            result.limitations.append("Aucune baseline d'intégrité fournie : seuls les hachages SHA-256 sont enregistrés")
        result.limitations.append(
            "Les dates de modification (mtime) peuvent être falsifiées et dépendent du fuseau de la source"
        )
        return result

    # -- per file -------------------------------------------------------------------
    def _inspect(self, path: Path, root: Path, result: DetectorResult) -> list[Finding]:
        st = path.lstat()
        rel = path.relative_to(root).as_posix() if path != root else path.name
        parts = [p.lower() for p in Path(rel).parts]
        in_upload = any(p in UPLOAD_DIR_NAMES for p in parts[:-1])
        mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
        ctx = _Ctx(path, rel, st, mtime, in_upload, result)
        if stat.S_ISLNK(st.st_mode):
            return self._symlink(ctx, root)
        if not stat.S_ISREG(st.st_mode):
            return []
        is_log = os.path.abspath(path) in self._log_files
        digest: str | None = None
        if st.st_size <= self.settings.max_hash_bytes:
            digest = sha256_file(path)
        else:
            result.limitations.append(f"Fichier trop volumineux pour le hachage ({st.st_size} octets) : {path}")
        ctx.sha = digest
        self.manifest.append({"path": rel, "sha256": digest, "size": st.st_size, "mtime": mtime.isoformat()})
        if is_log:
            return []
        findings: list[Finding] = []
        if digest and digest in self._ioc:
            findings.append(ctx.make(Category.IOC_HASH_MATCH, Severity.CRITICAL, 0.99, "File hash matches a known IOC", "ART-IOC", f"SHA-256 {digest} is in the supplied IOC list."))
        ext = path.suffix.lower()
        name = path.name.lower()
        findings.extend(self._placement(ctx, ext, name))
        head = read_head(path, 4096)
        findings.extend(self._mismatch(ctx, ext, name, head))
        if ext in SCRIPT_EXTENSIONS or _SCRIPT_MARKERS.search(head[:1024]):
            findings.extend(self._webshell(ctx))
        findings.extend(self._hidden(ctx, name, ext, st))
        findings.extend(self._times_and_perms(ctx, ext, st))
        return findings

    def _symlink(self, ctx: _Ctx, root: Path) -> list[Finding]:
        try:
            dest = os.readlink(ctx.path)
        except OSError:
            dest = "?"
        outside = not os.path.abspath(os.path.join(ctx.path.parent, dest)).startswith(os.path.abspath(root))
        if outside or ctx.in_upload:
            return [ctx.make(Category.SUSPICIOUS_FILE, Severity.LOW, 0.45, "Symbolic link not followed", "ART-SYMLINK", f"Symlink -> {dest} (outside tree: {outside}); target was not followed.")]
        return []

    def _placement(self, ctx: _Ctx, ext: str, name: str) -> list[Finding]:
        if not ctx.in_upload:
            return []
        if ext in EXECUTABLE_EXTENSIONS:
            return [ctx.make(Category.UPLOAD_EXEC, Severity.HIGH, 0.80, "Executable script in an upload directory", "ART-UPLOAD-EXEC", f"{ctx.rel} can be executed by the web server from a user-writable directory.")]
        if name in _SERVER_CONFIG_NAMES:
            return [ctx.make(Category.UPLOAD_EXEC, Severity.HIGH, 0.75, "Server configuration file in an upload directory", "ART-UPLOAD-CONFIG", f"{name} in an upload directory can re-enable script execution.")]
        return []

    def _mismatch(self, ctx: _Ctx, ext: str, name: str, head: bytes) -> list[Finding]:
        out: list[Finding] = []
        if _DOUBLE_EXT.search(name):
            out.append(ctx.make(Category.EXTENSION_MISMATCH, Severity.HIGH, 0.80, "Double/inconsistent file extension", "ART-DOUBLE-EXT", f"{ctx.path.name} mixes a script and a data extension."))
        if ext in DATA_EXTENSIONS:
            if _SCRIPT_MARKERS.search(head):
                out.append(ctx.make(Category.EXTENSION_MISMATCH, Severity.HIGH, 0.90 if ctx.in_upload else 0.85, "Script code inside a file with a data extension", "ART-SCRIPT-IN-DATA", f"{ext} file starts with server-side script markers."))
            elif head.startswith(b"\x7fELF") or (head.startswith(b"MZ") and b"PE\x00\x00" in head[:1024]):
                out.append(ctx.make(Category.EXTENSION_MISMATCH, Severity.HIGH, 0.80, "Native executable disguised as a data file", "ART-BINARY-IN-DATA", f"{ext} file has an ELF/PE header."))
        return out

    def _webshell(self, ctx: _Ctx) -> list[Finding]:
        verdict = scan_file(ctx.path, self.settings.max_scan_bytes)
        if not verdict.flagged or verdict.severity is None:
            return []
        confidence = min(0.97, verdict.confidence + (0.05 if ctx.in_upload else 0.0))
        finding = ctx.make(Category.WEBSHELL, verdict.severity, confidence, "Potential web shell", "ART-WEBSHELL", "; ".join(h.signature.description for h in verdict.hits))
        first = verdict.hits[0]
        finding.evidence.append(Evidence(str(ctx.path), first.line, sanitize_excerpt(first.excerpt), ctx.sha, "file_content"))
        finding.metadata.update({"signatures": [h.signature.id for h in verdict.hits], "entropy": round(verdict.entropy, 2)})
        return [finding]

    def _hidden(self, ctx: _Ctx, name: str, ext: str, st: os.stat_result) -> list[Finding]:
        hidden_file = name.startswith(".") and name not in BENIGN_HIDDEN_NAMES and name not in _SERVER_CONFIG_NAMES
        hidden_dir = any(p.startswith(".") and p not in BENIGN_HIDDEN_DIRS for p in Path(ctx.rel).parts[:-1])
        interesting = ctx.in_upload or ext in SCRIPT_EXTENSIONS or bool(st.st_mode & 0o111)
        if (hidden_file or hidden_dir) and interesting:
            return [ctx.make(Category.HIDDEN_FILE, Severity.MEDIUM, 0.55, "Suspicious hidden file", "ART-HIDDEN", f"Hidden {'file' if hidden_file else 'directory'} component in {ctx.rel}.")]
        return []

    def _times_and_perms(self, ctx: _Ctx, ext: str, st: os.stat_result) -> list[Finding]:
        out: list[Finding] = []
        days = self.settings.recent_days
        age = self._now - ctx.mtime
        if ext in SCRIPT_EXTENSIONS and timedelta(0) <= age <= timedelta(days=days):
            out.append(ctx.make(Category.RECENT_MODIFICATION, Severity.LOW, 0.40, f"Script modified within the last {days} days", "ART-RECENT", f"mtime {ctx.mtime.isoformat()} (reference {self._now.isoformat()})."))
        if ctx.mtime > self._now + timedelta(days=1):
            out.append(ctx.make(Category.SUSPICIOUS_FILE, Severity.LOW, 0.40, "Modification time in the future", "ART-FUTURE-MTIME", "Possible timestamp tampering."))
        if os.name != "nt":
            if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                out.append(ctx.make(Category.PERMISSIONS, Severity.HIGH, 0.70, "SUID/SGID file", "ART-SUID", f"mode {oct(st.st_mode & 0o7777)}"))
            elif ext in SCRIPT_EXTENSIONS and st.st_mode & stat.S_IWOTH:
                out.append(ctx.make(Category.PERMISSIONS, Severity.MEDIUM, 0.50, "World-writable script", "ART-WORLD-WRITABLE", f"mode {oct(st.st_mode & 0o7777)}"))
        return out

    def _integrity_findings(self, root: Path) -> list[Finding]:
        assert self._baseline is not None
        baseline = load_baseline(self._baseline)
        current = {m["path"]: m["sha256"] for m in self.manifest}
        diff = diff_manifests(current, baseline)
        src = str(root)
        findings: list[Finding] = []
        for items, sev, conf, title in (
            (diff.modified, Severity.HIGH, 0.90, "File modified since baseline"),
            (diff.added, Severity.MEDIUM, 0.60, "File added since baseline"),
            (diff.removed, Severity.LOW, 0.50, "File removed since baseline"),
        ):
            for rel in items:
                entry = next((m for m in self.manifest if m["path"] == rel), None)
                ts = datetime.fromisoformat(entry["mtime"]) if entry else None
                findings.append(Finding(
                    id=stable_id("F", "ART-INTEGRITY", rel, title), category=Category.INTEGRITY,
                    severity=sev, title=title, source=SourceType.ARTIFACT, confidence=conf, timestamp=ts,
                    source_file=str(root / rel), description=f"{rel}: {title.lower()}.",
                    evidence=[Evidence(src, None, sanitize_excerpt(f"{rel} sha256={current.get(rel) or baseline.get(rel)}"), current.get(rel), "file")],
                    rule_id="ART-INTEGRITY",
                    metadata={"relative_path": rel, "sha256": current.get(rel), "baseline_sha256": baseline.get(rel), "timestamp_kind": "mtime", "event_count": 1},
                ))
        return findings


class _Ctx:
    """Per-file context used to build findings consistently."""

    def __init__(self, path: Path, rel: str, st: os.stat_result, mtime: datetime, in_upload: bool, result: DetectorResult) -> None:
        self.path, self.rel, self.st, self.mtime, self.in_upload, self.result = path, rel, st, mtime, in_upload, result
        self.sha: str | None = None

    def make(self, category: Category, severity: Severity, confidence: float, title: str, rule_id: str, description: str) -> Finding:
        excerpt = f"{self.rel} size={self.st.st_size} sha256={self.sha or 'n/a'}"
        return Finding(
            id=stable_id("F", rule_id, str(self.path)),
            category=category, severity=severity, title=title, source=SourceType.ARTIFACT,
            confidence=confidence, timestamp=self.mtime, source_file=str(self.path),
            description=description,
            evidence=[Evidence(str(self.path), None, sanitize_excerpt(excerpt), self.sha, "file")],
            rule_id=rule_id,
            metadata={"relative_path": self.rel, "sha256": self.sha, "size": self.st.st_size,
                      "mtime": self.mtime.isoformat(), "timestamp_kind": "mtime", "in_upload_dir": self.in_upload,
                      "event_count": 1},
        )
