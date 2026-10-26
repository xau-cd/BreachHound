"""Integrity baselines: compare SHA-256 manifests (read-only on the target)."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from breachhound.core.exceptions import ConfigError


@dataclass
class IntegrityDiff:
    added: list[str] = field(default_factory=list)
    modified: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)


def load_baseline(path: Path) -> dict[str, str]:
    """Load ``{"files": {relative_path: sha256}}`` JSON."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        files = data["files"]
        return {str(k): str(v) for k, v in files.items()}
    except FileNotFoundError as exc:
        raise ConfigError(f"Baseline introuvable : {path}") from exc
    except (OSError, ValueError, KeyError, AttributeError, TypeError) as exc:
        raise ConfigError(f"Baseline invalide ({path}) : format attendu {{'files': {{chemin: sha256}}}}") from exc


def save_baseline(manifest: Mapping[str, str | None], path: Path) -> None:
    files = {k: v for k, v in sorted(manifest.items()) if v}
    path.write_text(json.dumps({"version": 1, "files": files}, indent=2), encoding="utf-8")


def diff_manifests(current: Mapping[str, str | None], baseline: Mapping[str, str]) -> IntegrityDiff:
    diff = IntegrityDiff()
    for rel, digest in sorted(current.items()):
        if rel not in baseline:
            diff.added.append(rel)
        elif digest is not None and digest != baseline[rel]:
            diff.modified.append(rel)
    diff.removed = sorted(rel for rel in baseline if rel not in current)
    return diff
