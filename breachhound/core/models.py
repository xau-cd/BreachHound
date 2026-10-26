"""Typed data models shared across BreachHound (stdlib dataclasses)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from breachhound.core.enums import (
    Category,
    RiskLevel,
    Severity,
    SourceType,
    confidence_label,
)


def stable_id(prefix: str, *parts: object) -> str:
    """Deterministic short identifier derived from its parts."""
    raw = "|".join("" if p is None else str(p) for p in parts)
    return f"{prefix}-{hashlib.sha256(raw.encode('utf-8', 'replace')).hexdigest()[:10]}"


def to_jsonable(value: Any) -> Any:
    """Recursively convert models, enums and datetimes to JSON-friendly types."""
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value) and not isinstance(value, type):
        return {f.name: to_jsonable(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (set, frozenset)):
        return sorted((to_jsonable(v) for v in value), key=str)
    if isinstance(value, (list, tuple)):
        return [to_jsonable(v) for v in value]
    return value


class JsonMixin:
    """Adds ``to_dict`` to dataclasses."""

    def to_dict(self) -> dict[str, Any]:
        result = to_jsonable(self)
        assert isinstance(result, dict)
        return result


@dataclass(frozen=True)
class Evidence(JsonMixin):
    """A verifiable excerpt tied to a source file (and optionally a line)."""

    source_file: str
    line: int | None
    excerpt: str
    sha256: str | None = None
    kind: str = "log_line"
    id: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            object.__setattr__(
                self, "id", stable_id("EV", self.source_file, self.line, self.excerpt)
            )


@dataclass
class Finding(JsonMixin):
    """A deterministic detection produced by a detector."""

    id: str
    category: Category
    severity: Severity
    title: str
    source: SourceType
    confidence: float
    timestamp: datetime | None = None
    source_file: str | None = None
    source_line: int | None = None
    ip: str | None = None
    user: str | None = None
    description: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    rule_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def confidence_level(self) -> str:
        return confidence_label(self.confidence)

    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()
        data["confidence_level"] = self.confidence_level
        return data


@dataclass
class TimelineEvent(JsonMixin):
    timestamp: datetime | None
    description: str
    severity: Severity
    category: Category
    source: SourceType
    ip: str | None = None
    finding_ids: list[str] = field(default_factory=list)
    count: int = 1
    approximate: bool = False


@dataclass
class Hypothesis(JsonMixin):
    """An explanation of what happened, always labelled with its basis."""

    statement: str
    basis: str  # "deterministic-correlation" | "llm"
    confidence: str  # LOW | MEDIUM | HIGH
    supporting_finding_ids: list[str] = field(default_factory=list)
    evidence_status: str = "supported"  # "supported" | "unsupported"
    note: str = ""


@dataclass
class Incident(JsonMixin):
    id: str
    title: str
    severity: Severity
    confidence: float
    finding_ids: list[str]
    ips: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    stages: list[str] = field(default_factory=list)
    start: datetime | None = None
    end: datetime | None = None
    link_reasons: dict[str, int] = field(default_factory=dict)
    probable_vector: str | None = None
    summary: str = ""
    hypotheses: list[Hypothesis] = field(default_factory=list)

    @property
    def confidence_level(self) -> str:
        return confidence_label(self.confidence)

    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()
        data["confidence_level"] = self.confidence_level
        return data


@dataclass
class RiskFactor(JsonMixin):
    name: str
    points: float
    detail: str = ""


@dataclass
class RiskAssessment(JsonMixin):
    score: int
    level: RiskLevel
    confidence: float
    factors: list[RiskFactor] = field(default_factory=list)
    formula: str = ""

    @property
    def confidence_level(self) -> str:
        return confidence_label(self.confidence)

    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()
        data["confidence_level"] = self.confidence_level
        return data


@dataclass
class LLMAnalysis(JsonMixin):
    """Outcome of the (optional) LLM stage. Never the single source of truth."""

    status: str = "not_requested"  # not_requested | ok | failed
    provider: str | None = None
    model: str | None = None
    error: str | None = None
    summary: str = ""
    probable_vector: str = ""
    hypotheses: list[Hypothesis] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)


@dataclass
class SourceFileInfo(JsonMixin):
    path: str
    kind: str
    sha256: str | None
    size: int | None


@dataclass
class InvestigationResult(JsonMixin):
    id: str
    target: str
    goal: str
    started_at: datetime
    finished_at: datetime
    tool_version: str
    findings: list[Finding] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)
    incidents: list[Incident] = field(default_factory=list)
    risk: RiskAssessment | None = None
    llm: LLMAnalysis = field(default_factory=LLMAnalysis)
    sources: list[SourceFileInfo] = field(default_factory=list)
    artifact_manifest: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    @property
    def ips(self) -> list[str]:
        return sorted({f.ip for f in self.findings if f.ip})
