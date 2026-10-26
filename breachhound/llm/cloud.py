"""Cloud provider: OpenAI-compatible chat API or Anthropic messages API."""

from __future__ import annotations

from typing import Any

from breachhound.core.exceptions import LLMError, LLMModelNotFoundError, LLMResponseError
from breachhound.llm.base import LLMProvider, LLMResponse

_ANTHROPIC_VERSION = "2023-06-01"


class CloudProvider(LLMProvider):
    name = "cloud"

    def __init__(
        self,
        *,
        endpoint: str,
        model: str,
        api_key: str,
        api_style: str = "openai",
        **kwargs: Any,
    ) -> None:
        super().__init__(model=model, **kwargs)
        if api_style not in ("openai", "anthropic"):
            raise ValueError(f"api_style inconnu : {api_style}")
        self.endpoint = endpoint.rstrip("/")
        self.api_style = api_style
        self._api_key = api_key

    def __repr__(self) -> str:  # never expose the key
        return f"CloudProvider(endpoint={self.endpoint!r}, model={self.model!r}, style={self.api_style!r})"

    def _headers(self) -> dict[str, str]:
        if self.api_style == "anthropic":
            return {
                "x-api-key": self._api_key,
                "anthropic-version": _ANTHROPIC_VERSION,
                "content-type": "application/json",
            }
        return {"Authorization": f"Bearer {self._api_key}", "content-type": "application/json"}

    def _url(self, path: str) -> str:
        base = self.endpoint
        if self.api_style == "anthropic" and not base.endswith("/v1"):
            base += "/v1"
        return f"{base}/{path}"

    def _not_found(self, body: str) -> LLMError:
        return LLMModelNotFoundError(
            f"Modèle ou endpoint introuvable (HTTP 404) : vérifiez « {self.model} » et l'endpoint"
        )

    def _request(self, system: str, prompt: str) -> LLMResponse:
        if self.api_style == "anthropic":
            payload: dict[str, Any] = {
                "model": self.model,
                "max_tokens": 2048,
                "temperature": 0.1,
                "system": system,
                "messages": [{"role": "user", "content": prompt}],
            }
            data = self._http_json("POST", self._url("messages"), headers=self._headers(), payload=payload)
            text = self._extract_anthropic(data)
        else:
            payload = {
                "model": self.model,
                "temperature": 0.1,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            }
            url = self.endpoint if self.endpoint.endswith("/chat/completions") else self._url("chat/completions")
            data = self._http_json("POST", url, headers=self._headers(), payload=payload)
            text = self._extract_openai(data)
        return LLMResponse(text=text, model=self.model, provider=self.name)

    @staticmethod
    def _extract_openai(data: Any) -> str:
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMResponseError("Structure de réponse OpenAI inattendue") from exc
        if not isinstance(content, str):
            raise LLMResponseError("Contenu de réponse invalide")
        return content

    @staticmethod
    def _extract_anthropic(data: Any) -> str:
        try:
            blocks = data["content"]
            parts = [b["text"] for b in blocks if isinstance(b, dict) and b.get("type") == "text"]
        except (KeyError, TypeError) as exc:
            raise LLMResponseError("Structure de réponse Anthropic inattendue") from exc
        return "".join(p for p in parts if isinstance(p, str))

    def healthcheck(self) -> str:
        self._http_json("GET", self._url("models"), headers=self._headers())
        return f"Endpoint cloud joignable et clé acceptée ({self.endpoint})"
