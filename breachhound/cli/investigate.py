"""``investigate`` command."""

from __future__ import annotations

import logging
from pathlib import Path

import click

from breachhound.cli.output import UI
from breachhound.config.providers import create_provider
from breachhound.config.settings import load_settings
from breachhound.config.validator import validate_settings
from breachhound.core.exceptions import ConfigError
from breachhound.engine.investigator import STAGES, InvestigationOptions, Investigator
from breachhound.reports.builder import write_reports
from breachhound.utils.filesystem import is_within
from breachhound.utils.logging import setup_logging
from breachhound.utils.timestamps import parse_iso_timestamp

_LLM_HINTS = ("cloud", "ollama", "Fournisseur", "Clé API", "Endpoint", "Modèle", "LLM_")


def _is_llm_issue(message: str) -> bool:
    return any(hint in message for hint in _LLM_HINTS)


_FAIL_ON = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def verbosity_options(func):  # type: ignore[no-untyped-def]
    func = click.option("--debug", is_flag=True, help="Détails techniques et traces d'erreur.")(func)
    return click.option("--verbose", "-v", is_flag=True, help="Journalisation détaillée.")(func)


def apply_verbosity(ctx: click.Context, verbose: bool, debug: bool) -> None:
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = ctx.obj.get("verbose", False) or verbose
    ctx.obj["debug"] = ctx.obj.get("debug", False) or debug
    setup_logging(ctx.obj["verbose"], ctx.obj["debug"])


@click.command("investigate")
@click.option("--target", "-t", required=True, type=click.Path(path_type=Path), help="Fichier ou répertoire à analyser (lecture seule).")
@click.option("--goal", "-g", default="Identifier le vecteur d'intrusion principal et la portée de l'incident", show_default=True)
@click.option("--output-dir", "-o", type=click.Path(path_type=Path), default=Path("reports"), show_default=True)
@click.option("--format", "formats", type=click.Choice(["md", "json", "both"]), default="both", show_default=True)
@click.option("--no-llm", is_flag=True, help="Désactiver l'analyse LLM (détecteurs seuls).")
@click.option("--env-file", type=click.Path(path_type=Path), help="Fichier .env à utiliser.")
@click.option("--baseline", type=click.Path(path_type=Path), help="Baseline d'intégrité JSON.")
@click.option("--ioc-hashes", type=click.Path(path_type=Path), help="Fichier de SHA-256 malveillants (un par ligne).")
@click.option("--reference-time", help="Date ISO de référence pour « récemment modifié » (défaut : maintenant).")
@click.option("--threshold", type=int, help="Seuil de brute-force (échecs).")
@click.option("--window", type=int, help="Fenêtre de brute-force (secondes).")
@click.option("--year", type=int, help="Année des logs syslog (défaut : déduite de la date du fichier).")
@click.option("--fail-on", type=click.Choice(["none", "low", "medium", "high", "critical"]), default="none", show_default=True, help="Code retour 10 si le niveau de risque atteint ce seuil.")
@click.option("--quiet", "-q", is_flag=True, help="Sortie minimale.")
@verbosity_options
@click.pass_context
def investigate_command(ctx: click.Context, target: Path, goal: str, output_dir: Path, formats: str, no_llm: bool,
                        env_file: Path | None, baseline: Path | None, ioc_hashes: Path | None,
                        reference_time: str | None, threshold: int | None, window: int | None, year: int | None,
                        fail_on: str, quiet: bool, verbose: bool, debug: bool) -> None:
    """Lance une investigation DFIR en lecture seule sur une cible."""
    apply_verbosity(ctx, verbose, debug)
    ui = UI(quiet=quiet)
    settings = load_settings(env_file)
    if threshold:
        settings.brute_force_threshold = threshold
    if window:
        settings.brute_force_window = window
    if year:
        settings.syslog_year = year
    issues = [i for i in validate_settings(settings) if i.level == "error"]
    generic = [i.message for i in issues if not _is_llm_issue(i.message)]
    if generic:
        raise ConfigError("Configuration invalide : " + " ; ".join(generic))
    provider = None
    llm_issues = [i.message for i in issues if _is_llm_issue(i.message)]
    if not no_llm and settings.llm_provider != "none":
        if llm_issues:
            ui.warning("configuration LLM invalide, l'analyse LLM sera ignorée : " + " ; ".join(llm_issues))
        else:
            provider = create_provider(settings)
    elif settings.llm_provider == "none" and not no_llm:
        ui.info("Aucun LLM configuré : investigation déterministe uniquement (python cli.py configure).")
    if is_within(output_dir, target) and target.is_dir():
        raise ConfigError("Le répertoire de sortie ne doit pas être dans la cible (lecture seule).")
    ref = None
    if reference_time:
        ref = parse_iso_timestamp(reference_time)
        if ref is None:
            raise ConfigError(f"--reference-time invalide : {reference_time!r} (format ISO 8601)")
    iocs: tuple[str, ...] = ()
    if ioc_hashes:
        try:
            iocs = tuple(line.strip().lower() for line in ioc_hashes.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#"))
        except OSError as exc:
            raise ConfigError(f"Fichier IOC illisible : {exc.strerror or exc}") from exc
    options = InvestigationOptions(use_llm=not no_llm, baseline=baseline, ioc_hashes=iocs, reference_time=ref)
    ui.info(f"Cible : {target}  |  Objectif : {goal}")
    with ui.progress(len(STAGES)) as progress:
        result = Investigator(settings, provider, progress).investigate(target, goal, options)
    fmts = ["md", "json"] if formats == "both" else [formats]
    paths = write_reports(result, output_dir, fmts)
    ui.summary(result, paths)
    logging.getLogger("breachhound").info("Investigation terminée (%s)", result.id)
    assert result.risk is not None
    if fail_on != "none" and result.risk.level.rank >= _FAIL_ON[fail_on]:
        ctx.exit(10)

