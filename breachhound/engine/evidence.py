"""Evidence helpers: sanitised excerpts and a registry of hashed source files."""

from __future__ import annotations

import re
from pathlib import Path

from breachhound.core.constants import EXCERPT_MAX
from breachhound.core.models import Evidence, SourceFileInfo
from breachhound.utils.hashing import sha256_file
from breachhound.utils.logging import redact_secrets

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_excerpt(text: str, limit: int = EXCERPT_MAX) -> str:
    """Make an excerpt safe to embed in reports (no control chars, secrets, code fences)."""
    cleaned = _CONTROL_RE.sub("?", text)
    cleaned = redact_secrets(cleaned).replace("```", "'''")
    if len(cleaned) > limit:
        cleaned = f"{cleaned[:limit]}... [+{len(cleaned) - limit} chars]"
    return cleaned


def build_evidence(
    source_file: str | Path,
    line: int | None,
    excerpt: str,
    *,
    sha256: str | None = None,
    kind: str = "log_line",
) -> Evidence:
    return Evidence(
        source_file=str(source_file),
        line=line,
        excerpt=sanitize_excerpt(excerpt),
        sha256=sha256,
        kind=kind,
    )


class SourceRegistry:
    """Records the SHA-256 of every analysed input (chain of custody)."""

    def __init__(self) -> None:
        self.sources: list[SourceFileInfo] = []
        self.problems: list[str] = []

    def register(self, path: Path, kind: str) -> SourceFileInfo | None:
        try:
            size = path.stat().st_size
            digest = sha256_file(path)
        except PermissionError:
            self.problems.append(f"Permission refusée (source non hachée) : {path}")
            return None
        except OSError as exc:
            self.problems.append(f"Source illisible ({exc.strerror or exc}) : {path}")
            return None
        info = SourceFileInfo(path=str(path), kind=kind, sha256=digest, size=size)
        self.sources.append(info)
        return info
