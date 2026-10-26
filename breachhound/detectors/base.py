"""Detector contracts shared by the web, auth and artifact analyzers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

from breachhound.config.settings import Settings
from breachhound.core.exceptions import BreachHoundError
from breachhound.core.models import Finding
from breachhound.utils.filesystem import walk_files


@dataclass
class DetectorResult:
    """Findings plus everything a detector could not verify."""

    findings: list[Finding] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    def merge(self, other: DetectorResult) -> None:
        self.findings.extend(other.findings)
        for item in other.limitations:
            if item not in self.limitations:
                self.limitations.append(item)
        for key, value in other.stats.items():
            current = self.stats.get(key)
            numeric = (int, float)
            if isinstance(value, numeric) and isinstance(current, numeric):
                self.stats[key] = current + value
            else:
                self.stats[key] = value


class Detector(ABC):
    """A deterministic analyzer. Detectors are strictly read-only."""

    name: ClassVar[str] = "detector"

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings()

    @abstractmethod
    def analyze(self, target: Path) -> DetectorResult:
        """Analyze a file or a directory."""


class LogDetector(Detector):
    """A detector working line by line on log files (streaming)."""

    @abstractmethod
    def accepts(self, path: Path) -> bool:
        """Return True when ``path`` looks like a log this detector understands."""

    @abstractmethod
    def analyze_file(self, path: Path) -> DetectorResult:
        """Analyze one file."""

    def analyze_files(self, files: Iterable[Path]) -> DetectorResult:
        merged = DetectorResult()
        for path in files:
            try:
                merged.merge(self.analyze_file(path))
            except BreachHoundError as exc:
                merged.limitations.append(f"{path}: {exc}")
            except OSError as exc:
                merged.limitations.append(f"{path}: {exc.strerror or exc}")
        return merged

    def analyze(self, target: Path) -> DetectorResult:
        if not target.is_dir():
            return self.analyze_files([target])
        errors: list[str] = []
        files = [p for p in walk_files(target, self.settings.max_files, errors) if self._ok(p)]
        result = self.analyze_files(files)
        result.limitations.extend(errors)
        return result

    def _ok(self, path: Path) -> bool:
        try:
            return path.is_file() and self.accepts(path)
        except OSError:
            return False
