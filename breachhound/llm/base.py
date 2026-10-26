"""LLM provider abstraction: the rest of the application only sees ``LLMProvider``."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import requests

from breachhound.core.exceptions import (
    LLMAuthError,
    LLMConnectionError,
    LLMError,
    LLMProviderError,
    LLMResponseError,
    LLMServerError,
    LLMTimeoutError,
)
from breachhound.utils.logging import redact_secrets


@dataclass(frozen=True)
class LLMResponse:
    text: str
    model: str
    provider: str


class LLMProvider(ABC):
    """Base class handling timeouts, retries and HTTP error mapping."""

    name = "base"

    def __init__(
        self,
        *,
        model: str,
        timeout: float = 60.0,
        retries: int = 2,
        backoff: float = 1.0,
        session: requests.Session | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.model = model
        self.timeout = timeout
        self.retries = max(0, retries)
        self.backoff = backoff
        self._session = session or requests.Session()
        self._sleep = sleep

    # -- public API -----------------------------------------------------------------
    def complete(self, system: str, prompt: str) -> LLMResponse:
        """Run a completion with bounded retries on transient errors."""
        attempts = self.retries + 1
        for attempt in range(attempts):
            try:
                response = self._request(system, prompt)
            except LLMError as exc:
                if not exc.retryable or attempt == attempts - 1:
                    raise
                self._sleep(self.backoff * (2**attempt))
                continue
            if not response.text.strip():
                raise LLMResponseError("Réponse vide du fournisseur LLM")
            return response
        raise LLMProviderError("Échec inattendu du fournisseur LLM")  # pragma: no cover

    @abstractmethod
    def _request(self, system: str, prompt: str) -> LLMResponse:
        """Perform one request (no retry)."""

    @abstractmethod
    def healthcheck(self) -> str:
        """Check connectivity/credentials. Raises ``LLMError`` on failure."""

    # -- HTTP helpers -----------------------------------------------------------------
    def _http_json(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        payload: dict[str, Any] | None = None,
    ) -> Any:
        timeout = (min(10.0, self.timeout), self.timeout)
        try:
            response = self._session.request(
                method, url, headers=headers, json=payload, timeout=timeout
            )
        except requests.Timeout as exc:
            raise LLMTimeoutError(
                f"Délai dépassé ({self.timeout:.0f}s) en contactant {self.name}"
            ) from exc
        except requests.ConnectionError as exc:
            raise self._connection_error(url) from exc
        except requests.RequestException as exc:
            raise LLMConnectionError(f"Erreur réseau vers {self.name} : {type(exc).__name__}") from exc
        self._raise_for_status(response)
        try:
            return response.json()
        except ValueError as exc:
            raise LLMResponseError(f"Réponse non-JSON de {self.name}") from exc

    def _connection_error(self, url: str) -> LLMError:
        return LLMConnectionError(f"Serveur {self.name} inaccessible ({url})")

    def _raise_for_status(self, response: Any) -> None:
        status = response.status_code
        if status < 400:
            return
        body = redact_secrets(str(getattr(response, "text", ""))[:200]).replace("\n", " ")
        if status in (401, 403):
            raise LLMAuthError(f"Clé API refusée par {self.name} (HTTP {status})")
        if status == 404:
            raise self._not_found(body)
        if status == 408:
            raise LLMTimeoutError(f"Délai dépassé côté serveur {self.name} (HTTP 408)")
        if status == 429 or status >= 500:
            raise LLMServerError(f"Erreur temporaire {self.name} (HTTP {status}) : {body}")
        raise LLMProviderError(f"Requête rejetée par {self.name} (HTTP {status}) : {body}")

    def _not_found(self, body: str) -> LLMError:
        return LLMProviderError(f"Ressource introuvable chez {self.name} (HTTP 404) : {body}")
