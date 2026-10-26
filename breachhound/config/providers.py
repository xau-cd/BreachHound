"""LLM provider presets and factory."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from breachhound.core.exceptions import ConfigError
from breachhound.llm.base import LLMProvider
from breachhound.llm.cloud import CloudProvider
from breachhound.llm.ollama import OllamaProvider

if TYPE_CHECKING:
    from breachhound.config.settings import Settings


@dataclass(frozen=True)
class ProviderPreset:
    key: str
    label: str
    api_style: str
    endpoint: str
    model: str


PRESETS: dict[str, ProviderPreset] = {
    "openai": ProviderPreset("openai", "OpenAI", "openai", "https://api.openai.com/v1", "gpt-4o-mini"),
    "anthropic": ProviderPreset(
        "anthropic", "Anthropic (Claude)", "anthropic", "https://api.anthropic.com", "claude-sonnet-5-5"
    ),
    "openrouter": ProviderPreset(
        "openrouter", "OpenRouter", "openai", "https://openrouter.ai/api/v1", "openai/gpt-4o-mini"
    ),
    "custom": ProviderPreset(
        "custom", "Endpoint compatible OpenAI", "openai", "http://localhost:1234/v1", "local-model"
    ),
}


def create_provider(settings: Settings) -> LLMProvider | None:
    """Build the configured provider (``None`` when the LLM is disabled)."""
    kind = settings.llm_provider
    if kind == "none":
        return None
    if kind == "cloud":
        if not settings.cloud_api_key:
            raise ConfigError("Clé API cloud manquante : lancez « python cli.py configure »")
        return CloudProvider(
            endpoint=settings.cloud_endpoint,
            model=settings.cloud_model,
            api_key=settings.cloud_api_key,
            api_style=settings.cloud_api_style,
            timeout=settings.llm_timeout,
            retries=settings.llm_retries,
        )
    if kind == "ollama":
        return OllamaProvider(
            endpoint=settings.ollama_endpoint,
            model=settings.ollama_model,
            timeout=settings.llm_timeout,
            retries=settings.llm_retries,
        )
    raise ConfigError(f"Fournisseur LLM inconnu : {kind!r} (none, cloud ou ollama)")
