"""Investigation pipeline: detectors -> correlation -> timeline -> risk -> LLM -> result."""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from breachhound.config.settings import Settings
from breachhound.core.constants import SCRIPT_EXTENSIONS
from breachhound.core.exceptions import FileAccessError, TargetNotFoundError
from breachhound.core.models import InvestigationResult, LLMAnalysis, stable_id
from breachhound.detectors.artifacts.checker import ArtifactChecker
from breachhound.detectors.auth.analyzer import AuthAnalyzer
from breachhound.detectors.auth.parser import looks_like_auth_log
from breachhound.detectors.base import DetectorResult
from breachhound.detectors.web.analyzer import WebAnalyzer
from breachhound.detectors.web.parser import looks_like_web_log
from breachhound.engine.correlator import Correlator
from breachhound.engine.evidence import SourceRegistry
from breachhound.engine.risk import RiskEngine
from breachhound.engine.timeline import build_timeline, sort_key
from breachhound.llm.analyzer import LLMAnalyzer
from breachhound.llm.base import LLMProvider
from breachhound.utils.filesystem import walk_files
from breachhound.utils.timestamps import utc_now
from breachhound.version import __version__

logger = logging.getLogger("breachhound.investigator")
ProgressCallback = Callable[[str, int, int], None]

STAGES = (
    "Découverte des sources",
    "Analyse des logs web",
    "Analyse des authentifications",
    "Analyse des artefacts",
    "Corrélation",
    "Chronologie et risque",
    "Analyse LLM",
)
_LOGISH_NAME = re.compile(r"(?:\.(?:log|txt)(?:\.\d+)?(?:\.gz)?|\.\d+|\.gz)$|^(?:auth|secure|syslog|messages|access|error)", re.I)


@dataclass
class InvestigationOptions:
    use_llm: bool = True
    baseline: Path | None = None
    ioc_hashes: tuple[str, ...] = ()
    reference_time: datetime | None = None


class Investigator:
    """Orchestrates a read-only investigation of a file or directory."""

    def __init__(
        self,
        settings: Settings | None = None,
        provider: LLMProvider | None = None,
        progress: ProgressCallback | None = None,
    ) -> None:
        self.settings = settings or Settings()
        self.provider = provider
        self._progress = progress or (lambda *_: None)

    def _step(self, index: int) -> None:
        self._progress(STAGES[index], index + 1, len(STAGES))

    def investigate(self, target: Path, goal: str, options: InvestigationOptions | None = None) -> InvestigationResult:
        opts = options or InvestigationOptions()
        started = utc_now()
        if not target.exists():
            raise TargetNotFoundError(f"Cible introuvable : {target}")
        target = target.resolve()
        limitations: list[str] = []

        self._step(0)
        web_files, auth_files, other = self._discover(target, limitations)
        registry = SourceRegistry()
        for p in web_files:
            registry.register(p, "web_log")
        for p in auth_files:
            registry.register(p, "auth_log")
        limitations.extend(registry.problems)

        detector_results: list[DetectorResult] = []
        self._step(1)
        web = WebAnalyzer(self.settings)
        detector_results.append(web.analyze_files(web_files))
        self._step(2)
        detector_results.append(AuthAnalyzer(self.settings).analyze_files(auth_files))
        self._step(3)
        manifest: list[dict[str, object]] = []
        if target.is_dir() or other:
            checker = ArtifactChecker(
                self.settings,
                log_files=[*web_files, *auth_files],
                baseline=opts.baseline,
                ioc_hashes=opts.ioc_hashes,
                reference_time=opts.reference_time,
            )
            detector_results.append(checker.analyze(target))
            manifest = list(checker.manifest)
        merged = DetectorResult()
        for r in detector_results:
            merged.merge(r)
        limitations.extend(x for x in merged.limitations if x not in limitations)
        if not web_files and not auth_files:
            limitations.append("Aucun log web ou d'authentification reconnu dans la cible.")
        limitations.extend(self._generic_limitations())

        self._step(4)
        findings = sorted(merged.findings, key=sort_key)
        correlator = Correlator(self.settings.correlation_window)
        incidents = correlator.build_incidents(correlator.correlate(findings))
        self._step(5)
        timeline = build_timeline(findings)
        risk = RiskEngine().assess(findings, incidents)

        result = InvestigationResult(
            id=stable_id("INV", str(target), started.isoformat()),
            target=str(target), goal=goal, started_at=started, finished_at=started,
            tool_version=__version__, findings=findings, timeline=timeline, incidents=incidents,
            risk=risk, sources=registry.sources, artifact_manifest=manifest, limitations=limitations,
            stats={**merged.stats, "findings_total": len(findings), "incidents_total": len(incidents)},
        )
        self._step(6)
        result.llm = self._llm(result, goal, opts.use_llm)
        if result.llm.status != "ok":
            reason = result.llm.error or "non demandée"
            result.limitations.append(f"Analyse LLM non effectuée : {reason}. Le rapport repose uniquement sur les détecteurs déterministes.")
        result.finished_at = utc_now()
        return result

    def _llm(self, result: InvestigationResult, goal: str, use_llm: bool) -> LLMAnalysis:
        if not use_llm:
            return LLMAnalysis(status="not_requested", error="désactivée (--no-llm)")
        if self.provider is None:
            return LLMAnalysis(status="not_requested", error="aucun fournisseur configuré (python cli.py configure)")
        analyzer = LLMAnalyzer(self.provider, language=self.settings.llm_language, max_findings=self.settings.llm_max_findings)
        return analyzer.analyze(result, goal)

    # -- discovery ----------------------------------------------------------------------
    def _discover(self, target: Path, limitations: list[str]) -> tuple[list[Path], list[Path], list[Path]]:
        errors: list[str] = []
        if target.is_file():
            candidates = [target]
        elif target.is_dir():
            candidates = list(walk_files(target, self.settings.max_files, errors))
        else:
            raise FileAccessError(f"Type de cible non pris en charge : {target}")
        limitations.extend(errors)
        web: list[Path] = []
        auth: list[Path] = []
        other: list[Path] = []
        for path in candidates:
            kind = self._classify(path)
            (web if kind == "web" else auth if kind == "auth" else other).append(path)
        return web, auth, other

    @staticmethod
    def _classify(path: Path) -> str:
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
                return "other"
            if path.suffix.lower() in SCRIPT_EXTENSIONS or not (_LOGISH_NAME.search(path.name) or "." not in path.name):
                return "other"
            if looks_like_web_log(path):
                return "web"
            if looks_like_auth_log(path):
                return "auth"
        except OSError:
            return "other"
        return "other"

    @staticmethod
    def _generic_limitations() -> list[str]:
        return [
            "Détection par signatures : une absence de finding ne prouve pas l'absence d'attaque.",
            "Un code HTTP 2xx indique une réponse du serveur, pas le succès d'une attaque.",
            "Les corps de requêtes POST ne figurent pas dans les logs d'accès : ils n'ont pas pu être analysés.",
            "La corrélation relie des indices (IP, fichier, temps) : elle n'établit pas une causalité.",
            "Les horodatages de sources différentes peuvent utiliser des fuseaux différents.",
        ]


__all__ = ["InvestigationOptions", "Investigator"]
