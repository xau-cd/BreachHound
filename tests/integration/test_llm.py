from __future__ import annotations

import json

import pytest
import requests

from breachhound.core.enums import Category, Severity, SourceType
from breachhound.core.exceptions import (
    LLMAuthError, LLMConnectionError, LLMModelNotFoundError, LLMResponseError, LLMServerError, LLMTimeoutError,
)
from breachhound.core.models import Finding, InvestigationResult
from breachhound.llm.analyzer import LLMAnalyzer, parse_llm_json
from breachhound.llm.cloud import CloudProvider
from breachhound.llm.ollama import OllamaProvider
from helpers import T0, StubProvider


class FakeResponse:
    def __init__(self, status=200, payload=None, text=None):
        self.status_code, self._payload = status, payload
        self.text = text if text is not None else json.dumps(payload)

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class FakeSession:
    def __init__(self, *outcomes):
        self.outcomes, self.calls = list(outcomes), []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        outcome = self.outcomes.pop(0) if len(self.outcomes) > 1 else self.outcomes[0]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def openai_ok(text="hello"):
    return FakeResponse(payload={"choices": [{"message": {"content": text}}]})


def cloud(session, **kw):
    return CloudProvider(endpoint="https://api.example.test/v1", model="m", api_key="sk-secret-key-123456",
                         session=session, sleep=lambda s: None, **kw)


def test_cloud_success_openai_and_anthropic():
    session = FakeSession(openai_ok("hi"))
    assert cloud(session).complete("s", "p").text == "hi"
    method, url, kwargs = session.calls[0]
    assert url.endswith("/v1/chat/completions") and kwargs["headers"]["Authorization"].startswith("Bearer ")
    anth = FakeSession(FakeResponse(payload={"content": [{"type": "text", "text": "yo"}]}))
    provider = CloudProvider(endpoint="https://api.anthropic.com", model="m", api_key="k" * 20, api_style="anthropic", session=anth)
    assert provider.complete("s", "p").text == "yo" and anth.calls[0][1] == "https://api.anthropic.com/v1/messages"
    assert "k" * 20 not in repr(provider)


def test_timeout_is_retried_then_raised():
    session = FakeSession(requests.Timeout("slow"))
    with pytest.raises(LLMTimeoutError):
        cloud(session, retries=2).complete("s", "p")
    assert len(session.calls) == 3


def test_retry_then_success():
    session = FakeSession(FakeResponse(500, text="boom"), openai_ok("fine"))
    assert cloud(session, retries=2).complete("s", "p").text == "fine" and len(session.calls) == 2


def test_auth_error_is_not_retried():
    session = FakeSession(FakeResponse(401, text="bad key sk-secret-key-123456"))
    with pytest.raises(LLMAuthError) as exc:
        cloud(session, retries=3).complete("s", "p")
    assert len(session.calls) == 1 and "sk-secret" not in str(exc.value)


def test_model_not_found_server_error_and_invalid_body():
    with pytest.raises(LLMModelNotFoundError):
        cloud(FakeSession(FakeResponse(404, text="no"))).complete("s", "p")
    with pytest.raises(LLMServerError):
        cloud(FakeSession(FakeResponse(503, text="down")), retries=0).complete("s", "p")
    with pytest.raises(LLMResponseError):
        cloud(FakeSession(FakeResponse(200, payload=None, text="<html>"))).complete("s", "p")
    with pytest.raises(LLMResponseError):
        cloud(FakeSession(FakeResponse(200, payload={"unexpected": 1}))).complete("s", "p")
    with pytest.raises(LLMResponseError):
        cloud(FakeSession(openai_ok("   "))).complete("s", "p")


def test_ollama_down_and_missing_model():
    down = OllamaProvider(endpoint="http://localhost:11434", model="llama3.1", session=FakeSession(requests.ConnectionError("refused")),
                          sleep=lambda s: None, retries=1)
    with pytest.raises(LLMConnectionError) as exc:
        down.complete("s", "p")
    assert "ollama serve" in str(exc.value)
    missing = OllamaProvider(endpoint="http://localhost:11434", model="nope", session=FakeSession(FakeResponse(404, text="model not found")))
    with pytest.raises(LLMModelNotFoundError):
        missing.complete("s", "p")
    ok = OllamaProvider(endpoint="http://localhost:11434", model="llama3.1",
                        session=FakeSession(FakeResponse(payload={"message": {"content": "{}"}})))
    assert ok.complete("s", "p").text == "{}"
    tags = OllamaProvider(endpoint="http://localhost:11434", model="llama3.1",
                          session=FakeSession(FakeResponse(payload={"models": [{"name": "llama3.1:latest"}]})))
    assert "disponible" in tags.healthcheck()


def make_result():
    f = Finding(id="F-real", category=Category.SQL_INJECTION, severity=Severity.HIGH, title="SQLi", source=SourceType.WEB,
                confidence=0.9, timestamp=T0, ip="198.51.100.1")
    return InvestigationResult(id="INV-1", target="t", goal="g", started_at=T0, finished_at=T0, tool_version="1", findings=[f])


def test_analyzer_success_grounds_hypotheses():
    answer = json.dumps({"summary": "SQLi seen", "probable_vector": "web", "recommendations": ["patch"],
                         "root_cause_hypotheses": [
                             {"hypothesis": "grounded", "supporting_finding_ids": ["F-real"], "confidence": "high"},
                             {"hypothesis": "invented", "supporting_finding_ids": ["F-ghost"], "confidence": "high"}]})
    analysis = LLMAnalyzer(StubProvider("```json\n" + answer + "\n```")).analyze(make_result(), "goal")
    assert analysis.status == "ok"
    grounded, invented = analysis.hypotheses
    assert grounded.evidence_status == "supported" and grounded.confidence == "HIGH"
    assert invented.evidence_status == "unsupported" and invented.confidence == "LOW" and not invented.supporting_finding_ids


@pytest.mark.parametrize("provider", [
    StubProvider(error=LLMTimeoutError("timeout")),
    StubProvider(error=LLMAuthError("bad key")),
    StubProvider(error=RuntimeError("boom")),
    StubProvider("this is not json"),
    StubProvider("[1, 2, 3]"),
    StubProvider("{}"),
])
def test_analyzer_never_raises(provider):
    analysis = LLMAnalyzer(provider).analyze(make_result(), "goal")
    assert analysis.status == "failed" and analysis.error


def test_parse_llm_json_tolerates_noise():
    assert parse_llm_json('Sure! {"a": 1} hope it helps')["a"] == 1
    with pytest.raises(LLMResponseError):
        parse_llm_json("nothing here")
