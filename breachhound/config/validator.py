"""Configuration validation."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from breachhound.config.settings import Settings
from breachhound.core.exceptions import ConfigError

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


@dataclass(frozen=True)
class ValidationIssue:
    level: str  # "error" | "warning"
    message: str


def _valid_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def validate_settings(settings: Settings) -> list[ValidationIssue]:
    """Return configuration problems (errors block the LLM stage, warnings do not)."""
    issues: list[ValidationIssue] = []

    def error(msg: str) -> None:
        issues.append(ValidationIssue("error", msg))

    def warn(msg: str) -> None:
        issues.append(ValidationIssue("warning", msg))

    if settings.llm_provider not in ("none", "cloud", "ollama"):
        error(f"Fournisseur inconnu : {settings.llm_provider!r} (none, cloud, ollama)")
    if settings.llm_provider == "cloud":
        if settings.cloud_api_style not in ("openai", "anthropic"):
            error("cloud_api_style doit valoir « openai » ou « anthropic »")
        if not _valid_url(settings.cloud_endpoint):
            error(f"Endpoint cloud invalide : {settings.cloud_endpoint!r}")
        elif urlparse(settings.cloud_endpoint).scheme == "http" and (
            urlparse(settings.cloud_endpoint).hostname not in _LOCAL_HOSTS
        ):
            warn("L'endpoint cloud utilise HTTP : la clé API circulerait en clair")
        if not settings.cloud_model.strip():
            error("Modèle cloud vide")
        if not settings.cloud_api_key:
            error("Clé API cloud manquante")
    if settings.llm_provider == "ollama":
        if not _valid_url(settings.ollama_endpoint):
            error(f"Endpoint Ollama invalide : {settings.ollama_endpoint!r}")
        if not settings.ollama_model.strip():
            error("Modèle Ollama vide")
    if settings.llm_timeout <= 0:
        error("BREACHHOUND_LLM_TIMEOUT doit être > 0")
    if settings.llm_retries < 0 or settings.llm_retries > 10:
        error("BREACHHOUND_LLM_RETRIES doit être compris entre 0 et 10")
    if settings.brute_force_threshold < 2:
        error("BREACHHOUND_BRUTE_FORCE_THRESHOLD doit être >= 2")
    for name in (
        "brute_force_window", "connection_burst_window", "web_error_burst_window",
        "correlation_window", "max_line_length", "max_lines", "max_findings", "max_files",
    ):  # fmt: skip
        if getattr(settings, name) <= 0:
            error(f"{name} doit être > 0")
    if settings.connection_burst_threshold < 2 or settings.web_error_burst_threshold < 2:
        error("Les seuils de burst doivent être >= 2")
    if settings.syslog_year is not None and not 1970 <= settings.syslog_year <= 2100:
        error("BREACHHOUND_SYSLOG_YEAR hors limites")
    return issues


def ensure_valid(settings: Settings) -> None:
    """Raise ``ConfigError`` listing every blocking problem."""
    errors = [i.message for i in validate_settings(settings) if i.level == "error"]
    if errors:
        raise ConfigError("Configuration invalide : " + " ; ".join(errors))
