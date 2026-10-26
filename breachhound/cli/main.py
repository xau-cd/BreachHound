"""BreachHound command line entry point."""

from __future__ import annotations

import importlib
import platform
import sys
from pathlib import Path
from typing import Any

import click

from breachhound.cli.configure import configure_command
from breachhound.cli.investigate import apply_verbosity, investigate_command, verbosity_options
from breachhound.cli.output import UI
from breachhound.config.settings import load_settings
from breachhound.config.validator import validate_settings
from breachhound.core.exceptions import BreachHoundError
from breachhound.version import __version__


class BreachHoundGroup(click.Group):
    """Turns expected errors into clean messages (no stack trace unless --debug)."""

    def invoke(self, ctx: click.Context) -> Any:
        try:
            return super().invoke(ctx)
        except BreachHoundError as exc:
            self._fail(ctx, str(exc), exc, exc.exit_code)
        except (click.ClickException, click.exceptions.Exit, click.Abort):
            raise
        except Exception as exc:  # noqa: BLE001 - last-resort handler
            self._fail(ctx, f"Erreur interne inattendue ({type(exc).__name__}). Relancez avec --debug pour les détails.", exc, 70)

    @staticmethod
    def _fail(ctx: click.Context, message: str, exc: BaseException, code: int) -> None:
        UI().error(message)
        if (ctx.obj or {}).get("debug"):
            raise exc
        ctx.exit(code)


@click.group(cls=BreachHoundGroup, context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--verbose", "-v", is_flag=True, help="Journalisation détaillée.")
@click.option("--debug", is_flag=True, help="Détails techniques et traces d'erreur.")
@click.pass_context
def cli(ctx: click.Context, verbose: bool, debug: bool) -> None:
    """BreachHound - investigation DFIR/SOC (lecture seule) sur logs et artefacts."""
    apply_verbosity(ctx, verbose, debug)


@cli.command("version")
def version_command() -> None:
    """Affiche la version."""
    click.echo(f"BreachHound {__version__}")


@cli.command("doctor")
@click.option("--env-file", type=click.Path(path_type=Path), help="Fichier .env à utiliser.")
@click.option("--offline", is_flag=True, help="Ne pas tester la connexion au LLM.")
@verbosity_options
@click.pass_context
def doctor_command(ctx: click.Context, env_file: Path | None, offline: bool, verbose: bool, debug: bool) -> None:
    """Vérifie l'environnement, la configuration et la connexion LLM."""
    apply_verbosity(ctx, verbose, debug)
    ui = UI()
    rows: list[list[str]] = [["Python", f"{platform.python_version()}", "OK" if sys.version_info >= (3, 10) else "ÉCHEC (>= 3.10 requis)"]]
    for module in ("click", "rich", "jinja2", "requests", "dotenv"):
        try:
            importlib.import_module(module)
            rows.append([f"module {module}", "installé", "OK"])
        except ImportError:
            rows.append([f"module {module}", "absent", "ÉCHEC (pip install -r requirements.txt)"])
    settings = load_settings(env_file)
    for issue in validate_settings(settings):
        rows.append(["configuration", issue.message, "ÉCHEC" if issue.level == "error" else "AVERTISSEMENT"])
    rows.append(["fournisseur LLM", settings.llm_provider, "OK"])
    if settings.llm_provider != "none" and not offline and not any(i.level == "error" for i in validate_settings(settings)):
        from breachhound.config.providers import create_provider

        provider = create_provider(settings)
        try:
            assert provider is not None
            rows.append(["connexion LLM", provider.healthcheck(), "OK"])
        except BreachHoundError as exc:
            rows.append(["connexion LLM", str(exc), "ÉCHEC"])
    ui.table("BreachHound doctor", ["Contrôle", "Détail", "État"], rows)


cli.add_command(configure_command)
cli.add_command(investigate_command)


def main() -> None:
    cli(prog_name="cli.py")


if __name__ == "__main__":  # pragma: no cover
    main()
