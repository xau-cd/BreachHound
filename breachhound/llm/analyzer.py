"""LLM-assisted interpretation. Fails soft: it can never break an investigation."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from breachhound.core.exceptions import BreachHoundError, LLMResponseError
from breachhound.core.models import Hypothesis, InvestigationResult, LLMAnalysis
from breachhound.engine.evidence import sanitize_excerpt
from breachhound.llm.base import LLMProvider
from breachhound.llm.prompts import SYSTEM_PROMPT, build_user_prompt

logger = logging.getLogger("breachhound.llm")

_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE)
_CONF = {"low": "LOW", "medium": "MEDIUM", "high": "HIGH"}


def parse_llm_json(text: str) -> dict[str, Any]:
    """Extract the JSON object from a model answer (tolerates fences and chatter)."""
    cleaned = _FENCE_RE.sub("", text.strip()).strip()
    candidates = [cleaned]
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start != -1 and end > start:
        candidates.append(cleaned[start : end + 1])
    for candidate in candidates:
        try:
            data = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(data, dict):
            return data
    raise LLMResponseError("La réponse du LLM n'est pas un objet JSON valide")


def _str_list(value: Any, limit: int = 15) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(v).strip()[:500] for v in value if isinstance(v, (str, int, float)) and str(v).strip()][
        :limit
    ]


class LLMAnalyzer:
    def __init__(
        self,
        provider: LLMProvider | None,
        *,
        language: str = "fr",
        max_findings: int = 40,
    ) -> None:
        self.provider = provider
        self.language = language
        self.max_findings = max_findings

    def build_context(self, result: InvestigationResult) -> dict[str, Any]:
        ranked = sorted(
            result.findings,
            key=lambda f: (f.severity.rank, f.confidence),
            reverse=True,
        )[: self.max_findings]
        return {
            "risk": {
                "score": result.risk.score if result.risk else None,
                "level": result.risk.level.value if result.risk else None,
            },
            "incidents": [
                {
                    "id": i.id,
                    "severity": i.severity.value,
                    "stages": i.stages,
                    "ips": i.ips,
                    "finding_ids": i.finding_ids[:30],
                    "probable_vector_deterministic": i.probable_vector,
                }
                for i in result.incidents
            ],
            "findings": [
                {
                    "id": f.id,
                    "time": f.timestamp.isoformat() if f.timestamp else None,
                    "severity": f.severity.value,
                    "category": f.category.value,
                    "title": f.title,
                    "ip": f.ip,
                    "user": f.user,
                    "confidence": round(f.confidence, 2),
                    "excerpt": sanitize_excerpt(f.evidence[0].excerpt, 300) if f.evidence else "",
                }
                for f in ranked
            ],
            "limitations": result.limitations[:10],
        }

    def analyze(self, result: InvestigationResult, goal: str) -> LLMAnalysis:
        if self.provider is None:
            return LLMAnalysis(status="not_requested", error="Aucun fournisseur LLM configuré")
        analysis = LLMAnalysis(status="failed", provider=self.provider.name, model=self.provider.model)
        try:
            context = self.build_context(result)
            prompt = build_user_prompt(context, goal, self.language)
            response = self.provider.complete(SYSTEM_PROMPT, prompt)
            data = parse_llm_json(response.text)
            valid_ids = {f.id for f in result.findings}
            self._fill(analysis, data, valid_ids)
            analysis.status = "ok"
        except BreachHoundError as exc:
            analysis.error = str(exc)
            logger.warning("LLM analysis failed: %s", exc)
        except Exception as exc:  # noqa: BLE001 - the LLM stage must never crash the run
            analysis.error = f"Erreur inattendue pendant l'analyse LLM : {type(exc).__name__}"
            logger.warning("Unexpected LLM failure: %s", type(exc).__name__)
        return analysis

    @staticmethod
    def _fill(analysis: LLMAnalysis, data: dict[str, Any], valid_ids: set[str]) -> None:
        analysis.summary = str(data.get("summary", "")).strip()[:2000]
        analysis.probable_vector = str(data.get("probable_vector", "")).strip()[:300]
        analysis.recommendations = _str_list(data.get("recommendations"))
        analysis.gaps = _str_list(data.get("gaps"))
        raw = data.get("root_cause_hypotheses")
        for item in raw if isinstance(raw, list) else []:
            if not isinstance(item, dict) or not str(item.get("hypothesis", "")).strip():
                continue
            cited = item.get("supporting_finding_ids")
            ids = [i for i in cited if isinstance(i, str) and i in valid_ids] if isinstance(cited, list) else []
            confidence = _CONF.get(str(item.get("confidence", "low")).lower(), "LOW")
            supported = bool(ids)
            analysis.hypotheses.append(
                Hypothesis(
                    statement=str(item["hypothesis"]).strip()[:600],
                    basis="llm",
                    confidence=confidence if supported else "LOW",
                    supporting_finding_ids=ids,
                    evidence_status="supported" if supported else "unsupported",
                    note="" if supported else "No deterministic finding supports this hypothesis: speculation.",
                )
            )
        if not (analysis.summary or analysis.hypotheses):
            raise LLMResponseError("Réponse du LLM vide ou hors schéma")
