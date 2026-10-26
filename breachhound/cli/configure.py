"""``configure`` command: interactive or scripted LLM configuration."""

from __future__ import annotations

from pathlib import Path

import click

from breachhound.cli.output import UI
from breachhound.config.providers import PRESETS
from breachhound.config.settings import load_settings, update_env_file
from breachhound.config.validator import validate_settings
from breachhound.core.exceptions import ConfigError


@click.command("configure")
@click.option("--env-file", type=click.Path(path_type=Path), default=Path(".env"), show_default=True, help="Fichier .env à écrire.")
@click.option("--provider", type=click.Choice(["none", "cloud", "ollama"]), help="Fournisseur LLM.")
@click.option("--preset", type=click.Choice(sorted(PRESETS)), help="Préréglage cloud.")
@click.option("--endpoint", help="Endpoint (cloud ou Ollama).")
@click.option("--model", help="Nom du modèle.")
@click.option("--api-key", help="Clé API cloud (préférez la saisie interactive masquée).")
@click.option("--non-interactive", is_flag=True, help="Ne rien demander : n'utiliser que les options.")
def configure_command(env_file: Path, provider: str | None, preset: str | None, endpoint: str | None,
                      model: str | None, api_key: str | None, non_interactive: bool) -> None:
    """Configure le fournisseur LLM (Cloud ou Ollama) dans un fichier .env."""
    ui = UI()
    current = load_settings(env_file if env_file.is_file() else None, environ={})
    if provider is None:
        if non_interactive:
            raise ConfigError("--provider est requis avec --non-interactive")
        provider = click.prompt("Fournisseur LLM", type=click.Choice(["none", "cloud", "ollama"]), default=current.llm_provider)
    updates: dict[str, str] = {"BREACHHOUND_LLM_PROVIDER": provider}
    if provider == "cloud":
        if preset is None and not non_interactive:
            preset = click.prompt("Préréglage", type=click.Choice(sorted(PRESETS)), default=current.cloud_preset)
        chosen = PRESETS.get(preset or current.cloud_preset, PRESETS["openai"])
        if endpoint is None and not non_interactive:
            endpoint = click.prompt("Endpoint", default=chosen.endpoint)
        if model is None and not non_interactive:
            model = click.prompt("Modèle", default=chosen.model)
        if api_key is None and not non_interactive:
            api_key = click.prompt("Clé API (saisie masquée)", hide_input=True, default="", show_default=False) or None
        updates.update({
            "BREACHHOUND_CLOUD_PRESET": chosen.key,
            "BREACHHOUND_CLOUD_API_STYLE": chosen.api_style,
            "BREACHHOUND_CLOUD_ENDPOINT": endpoint or chosen.endpoint,
            "BREACHHOUND_CLOUD_MODEL": model or chosen.model,
        })
        if api_key:
            updates["BREACHHOUND_CLOUD_API_KEY"] = api_key
    elif provider == "ollama":
        if endpoint is None and not non_interactive:
            endpoint = click.prompt("Endpoint Ollama", default=current.ollama_endpoint)
        if model is None and not non_interactive:
            model = click.prompt("Modèle Ollama", default=current.ollama_model)
        updates["BREACHHOUND_OLLAMA_ENDPOINT"] = endpoint or current.ollama_endpoint
        updates["BREACHHOUND_OLLAMA_MODEL"] = model or current.ollama_model
    update_env_file(env_file, updates)
    new = load_settings(env_file, environ={})
    ui.success(f"Configuration enregistrée dans {env_file} (permissions restreintes).")
    masked = new.masked()
    ui.table("Configuration", ["Paramètre", "Valeur"], [[k, str(masked[k])] for k in (
        "llm_provider", "cloud_preset", "cloud_endpoint", "cloud_model", "cloud_api_key", "ollama_endpoint", "ollama_model")])
    for issue in validate_settings(new):
        (ui.warning if issue.level == "warning" else ui.error)(issue.message)
