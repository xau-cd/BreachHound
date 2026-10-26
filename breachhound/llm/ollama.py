"""Local Ollama provider."""

from __future__ import annotations

from typing import Any

from breachhound.core.exceptions import (
    LLMConnectionError,
    LLMError,
    LLMModelNotFoundError,
    LLMResponseError,
)
from breachhound.llm.base import LLMProvider, LLMResponse


class OllamaProvider(LLMProvider):
    name = "ollama"

    def __init__(self, *, endpoint: str, model: str, **kwargs: Any) -> None:
        super().__init__(model=model, **kwargs)
        self.endpoint = endpoint.rstrip("/")

    def _connection_error(self, url: str) -> LLMError:
        return LLMConnectionError(
            f"Ollama est inaccessible sur {self.endpoint} (démarrez-le avec « ollama serve »)"
        )

    def _not_found(self, body: str) -> LLMError:
        return LLMModelNotFoundError(
            f"Modèle Ollama introuvable : {self.model} (installez-le avec « ollama pull {self.model} »)"
        )

    def _request(self, system: str, prompt: str) -> LLMResponse:
        payload = {
            "model": self.model,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.1},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
        }
        data = self._http_json("POST", f"{self.endpoint}/api/chat", payload=payload)
        try:
            text = data["message"]["content"]
        except (KeyError, TypeError) as exc:
            raise LLMResponseError("Structure de réponse Ollama inattendue") from exc
        if not isinstance(text, str):
            raise LLMResponseError("Contenu de réponse Ollama invalide")
        return LLMResponse(text=text, model=self.model, provider=self.name)

    def healthcheck(self) -> str:
        data = self._http_json("GET", f"{self.endpoint}/api/tags")
        try:
            names = {m["name"] for m in data.get("models", [])}
        except (AttributeError, KeyError, TypeError) as exc:
            raise LLMResponseError("Réponse /api/tags invalide") from exc
        wanted = {self.model, f"{self.model}:latest"}
        if not names & wanted:
            raise LLMModelNotFoundError(
                f"Ollama répond mais le modèle « {self.model} » n'est pas installé"
            )
        return f"Ollama joignable, modèle {self.model} disponible"
