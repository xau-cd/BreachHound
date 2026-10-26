"""Settings loaded from ``.env`` / environment variables."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dotenv import dotenv_values

from breachhound.config.providers import PRESETS
from breachhound.core import constants as c
from breachhound.core.exceptions import ConfigError

ENV_PREFIX = "BREACHHOUND_"

_FIELD_ENV: dict[str, str] = {
    "llm_provider": "BREACHHOUND_LLM_PROVIDER",
    "cloud_preset": "BREACHHOUND_CLOUD_PRESET",
    "cloud_api_style": "BREACHHOUND_CLOUD_API_STYLE",
    "cloud_endpoint": "BREACHHOUND_CLOUD_ENDPOINT",
    "cloud_model": "BREACHHOUND_CLOUD_MODEL",
    "cloud_api_key": "BREACHHOUND_CLOUD_API_KEY",
    "ollama_endpoint": "BREACHHOUND_OLLAMA_ENDPOINT",
    "ollama_model": "BREACHHOUND_OLLAMA_MODEL",
    "llm_timeout": "BREACHHOUND_LLM_TIMEOUT",
    "llm_retries": "BREACHHOUND_LLM_RETRIES",
    "llm_language": "BREACHHOUND_LANGUAGE",
    "llm_max_findings": "BREACHHOUND_LLM_MAX_FINDINGS",
    "brute_force_threshold": "BREACHHOUND_BRUTE_FORCE_THRESHOLD",
    "brute_force_window": "BREACHHOUND_BRUTE_FORCE_WINDOW",
    "connection_burst_threshold": "BREACHHOUND_CONNECTION_BURST_THRESHOLD",
    "connection_burst_window": "BREACHHOUND_CONNECTION_BURST_WINDOW",
    "slow_brute_force_total": "BREACHHOUND_SLOW_BRUTE_FORCE_TOTAL",
    "web_error_burst_threshold": "BREACHHOUND_WEB_ERROR_BURST_THRESHOLD",
    "web_error_burst_window": "BREACHHOUND_WEB_ERROR_BURST_WINDOW",
    "max_line_length": "BREACHHOUND_MAX_LINE_LENGTH",
    "max_lines": "BREACHHOUND_MAX_LINES",
    "max_findings": "BREACHHOUND_MAX_FINDINGS",
    "max_files": "BREACHHOUND_MAX_FILES",
    "max_hash_bytes": "BREACHHOUND_MAX_HASH_BYTES",
    "max_scan_bytes": "BREACHHOUND_MAX_SCAN_BYTES",
    "recent_days": "BREACHHOUND_RECENT_DAYS",
    "correlation_window": "BREACHHOUND_CORRELATION_WINDOW",
    "syslog_year": "BREACHHOUND_SYSLOG_YEAR",
}
_FLOAT_FIELDS = {"llm_timeout"}
_INT_FIELDS = {
    "llm_retries", "llm_max_findings", "brute_force_threshold", "brute_force_window",
    "connection_burst_threshold", "connection_burst_window", "slow_brute_force_total",
    "web_error_burst_threshold", "web_error_burst_window", "max_line_length", "max_lines",
    "max_findings", "max_files", "max_hash_bytes", "max_scan_bytes", "recent_days",
    "correlation_window", "syslog_year",
}  # fmt: skip


@dataclass
class Settings:
    """Runtime configuration. The API key is never part of ``repr``."""

    llm_provider: str = "none"  # none | cloud | ollama
    cloud_preset: str = "openai"
    cloud_api_style: str = "openai"  # openai | anthropic
    cloud_endpoint: str = "https://api.openai.com/v1"
    cloud_model: str = "gpt-4o-mini"
    cloud_api_key: str | None = field(default=None, repr=False)
    ollama_endpoint: str = "http://localhost:11434"
    ollama_model: str = "llama3.1"
    llm_timeout: float = c.DEFAULT_LLM_TIMEOUT
    llm_retries: int = c.DEFAULT_LLM_RETRIES
    llm_language: str = "fr"
    llm_max_findings: int = 40
    brute_force_threshold: int = c.DEFAULT_BRUTE_FORCE_THRESHOLD
    brute_force_window: int = c.DEFAULT_BRUTE_FORCE_WINDOW
    connection_burst_threshold: int = c.DEFAULT_CONNECTION_BURST_THRESHOLD
    connection_burst_window: int = c.DEFAULT_CONNECTION_BURST_WINDOW
    slow_brute_force_total: int = c.DEFAULT_SLOW_BRUTE_FORCE_TOTAL
    web_error_burst_threshold: int = c.DEFAULT_WEB_ERROR_BURST_THRESHOLD
    web_error_burst_window: int = c.DEFAULT_WEB_ERROR_BURST_WINDOW
    max_line_length: int = c.DEFAULT_MAX_LINE_LENGTH
    max_lines: int = c.DEFAULT_MAX_LINES
    max_findings: int = c.DEFAULT_MAX_FINDINGS
    max_files: int = c.DEFAULT_MAX_FILES
    max_hash_bytes: int = c.DEFAULT_MAX_HASH_BYTES
    max_scan_bytes: int = c.DEFAULT_MAX_SCAN_BYTES
    recent_days: int = c.DEFAULT_RECENT_DAYS
    correlation_window: int = c.DEFAULT_CORRELATION_WINDOW
    syslog_year: int | None = None

    @classmethod
    def from_mapping(cls, env: Mapping[str, str | None]) -> Settings:
        kwargs: dict[str, Any] = {}
        for attr, key in _FIELD_ENV.items():
            raw = env.get(key)
            if raw is None or not raw.strip():
                continue
            raw = raw.strip()
            try:
                if attr in _INT_FIELDS:
                    kwargs[attr] = int(raw)
                elif attr in _FLOAT_FIELDS:
                    kwargs[attr] = float(raw)
                else:
                    kwargs[attr] = raw
            except ValueError as exc:
                raise ConfigError(f"Valeur invalide pour {key} : {raw!r}") from exc
        preset = PRESETS.get(str(kwargs.get("cloud_preset", "")).lower())
        if preset is not None:
            kwargs.setdefault("cloud_api_style", preset.api_style)
            kwargs.setdefault("cloud_endpoint", preset.endpoint)
            kwargs.setdefault("cloud_model", preset.model)
        settings = cls(**kwargs)
        settings.llm_provider = settings.llm_provider.lower()
        settings.cloud_api_style = settings.cloud_api_style.lower()
        return settings

    def masked(self) -> dict[str, Any]:
        """Settings as a dict with the API key masked (safe to display or log)."""
        data = {attr: getattr(self, attr) for attr in _FIELD_ENV}
        key = self.cloud_api_key
        data["cloud_api_key"] = None if not key else f"****{key[-4:]}" if len(key) > 12 else "****"
        return data


def load_settings(
    env_file: Path | None = None, environ: Mapping[str, str] | None = None
) -> Settings:
    """Load settings from a ``.env`` file (default ``./.env``) and the environment."""
    merged: dict[str, str | None] = {}
    path = env_file if env_file is not None else Path(".env")
    if path.is_file():
        try:
            merged.update(dotenv_values(path))
        except (OSError, UnicodeDecodeError) as exc:
            raise ConfigError(f"Impossible de lire {path} : {exc}") from exc
    elif env_file is not None:
        raise ConfigError(f"Fichier de configuration introuvable : {env_file}")
    merged.update(environ if environ is not None else os.environ)
    return Settings.from_mapping(merged)


def _quote(value: str) -> str:
    if re.search(r"[\s#\x27\x22\\]", value):
        escaped = value.replace("\\", "\\\\").replace("'", "\\'")
        return f"'{escaped}'"
    return value


def update_env_file(path: Path, updates: Mapping[str, str]) -> None:
    """Create/update ``KEY=value`` lines in a ``.env`` file (mode 0600, atomic)."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"Impossible de lire {path} : {exc}") from exc
    remaining = dict(updates)
    out: list[str] = []
    for line in lines:
        match = re.match(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
        if match and match.group(1) in remaining:
            key = match.group(1)
            out.append(f"{key}={_quote(remaining.pop(key))}")
        else:
            out.append(line)
    out.extend(f"{key}={_quote(value)}" for key, value in remaining.items())
    tmp = path.with_name(path.name + ".tmp")
    try:
        tmp.write_text("\n".join(out) + "\n", encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, path)
    except OSError as exc:
        raise ConfigError(f"Impossible d'écrire {path} : {exc.strerror or exc}") from exc
