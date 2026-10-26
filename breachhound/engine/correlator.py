"""Correlation of findings into incidents (IP, time, file, user, stage)."""

from __future__ import annotations

import bisect
from collections import Counter, defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone

from breachhound.core.enums import STAGE_ORDER, Category, Severity, Stage, stage_of
from breachhound.core.models import Finding, Hypothesis, Incident, stable_id
from breachhound.engine.timeline import sort_key

_C = Category
_ENTRY = (_C.REMOTE_CODE_EXECUTION, _C.SQL_INJECTION, _C.PATH_TRAVERSAL, _C.AUTH_SUCCESS_AFTER_BRUTE_FORCE,
          _C.BRUTE_FORCE, _C.XSS)  # fmt: skip
_ANCHOR_STAGES = {Stage.EXPLOITATION, Stage.CREDENTIAL_ACCESS, Stage.INITIAL_ACCESS, Stage.UPLOAD, Stage.WEBSHELL}
_POST_STAGES = {Stage.UPLOAD, Stage.WEBSHELL, Stage.PRIVILEGE_ESCALATION, Stage.TAMPERING}
_NO_USER = {None, "", "-", "?"}
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class _DSU:
    def __init__(self, n: int) -> None:
        self.p = list(range(n))

    def find(self, x: int) -> int:
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[rb] = ra


@dataclass
class CorrelationGroup:
    findings: list[Finding]
    reasons: Counter[str] = field(default_factory=Counter)

    @property
    def strong(self) -> bool:
        return self.reasons["same_ip"] + self.reasons["same_file"] > 0


def _path_key(path: str | None) -> str | None:
    if not path:
        return None
    parts = [p for p in path.split("?")[0].replace("\\", "/").lower().split("/") if p]
    return "/".join(parts[-2:]) if parts else None


class Correlator:
    def __init__(self, window_seconds: int = 3600) -> None:
        self.window = window_seconds

    def correlate(self, findings: Sequence[Finding]) -> list[CorrelationGroup]:
        n = len(findings)
        dsu = _DSU(n)
        edges: list[tuple[int, int, str]] = []

        def link(a: int, b: int, reason: str) -> None:
            dsu.union(a, b)
            edges.append((a, b, reason))

        def near(a: int, b: int) -> bool:
            ta, tb = findings[a].timestamp, findings[b].timestamp
            return ta is None or tb is None or abs((tb - ta).total_seconds()) <= self.window

        by_ip: dict[str, list[int]] = defaultdict(list)
        by_file: dict[str, list[int]] = defaultdict(list)
        by_user: dict[str, list[int]] = defaultdict(list)
        for i, f in enumerate(findings):
            if f.ip:
                by_ip[f.ip].append(i)
            key = _path_key(f.metadata.get("request_path") or f.metadata.get("relative_path"))
            if key:
                by_file[key].append(i)
            if f.user not in _NO_USER:
                by_user[str(f.user)].append(i)
        for groups, reason, gate in ((by_ip, "same_ip", True), (by_file, "same_file", False), (by_user, "same_user", True)):
            for idxs in groups.values():
                idxs.sort(key=lambda i: sort_key(findings[i]))
                for a, b in zip(idxs, idxs[1:], strict=False):
                    if not gate or near(a, b):
                        link(a, b, reason)
        anchors = sorted(
            (i for i, f in enumerate(findings)
             if f.ip and f.timestamp and f.severity.rank >= Severity.MEDIUM.rank and stage_of(f.category) in _ANCHOR_STAGES),
            key=lambda i: findings[i].timestamp or _EPOCH,
        )
        times = [findings[i].timestamp or _EPOCH for i in anchors]
        for i, f in enumerate(findings):
            if f.ip or not f.timestamp or stage_of(f.category) not in _POST_STAGES:
                continue
            pos = bisect.bisect_right(times, f.timestamp) - 1
            if pos >= 0 and (f.timestamp - times[pos]).total_seconds() <= self.window:
                link(i, anchors[pos], "temporal_proximity")
        members: dict[int, list[int]] = defaultdict(list)
        for i in range(n):
            members[dsu.find(i)].append(i)
        reasons: dict[int, Counter[str]] = defaultdict(Counter)
        for a, _b, reason in edges:
            reasons[dsu.find(a)][reason] += 1
        groups_out = [
            CorrelationGroup(sorted((findings[i] for i in idxs), key=sort_key), reasons[root])
            for root, idxs in members.items()
        ]
        groups_out.sort(key=lambda g: (-max(f.severity.rank for f in g.findings), sort_key(g.findings[0])))
        return groups_out

    def build_incidents(self, groups: Sequence[CorrelationGroup]) -> list[Incident]:
        incidents = []
        for g in groups:
            top = max(f.severity.rank for f in g.findings)
            stages = self._stages(g.findings)
            if top < Severity.MEDIUM.rank:
                continue
            incidents.append(self._incident(g, stages))
        incidents.sort(key=lambda i: (-i.severity.rank, -i.confidence))
        return incidents

    @staticmethod
    def _stages(findings: Sequence[Finding]) -> list[str]:
        first: dict[Stage, datetime | None] = {}
        for f in findings:
            st = stage_of(f.category)
            if st not in first:
                first[st] = f.timestamp
            elif f.timestamp and (first[st] is None or f.timestamp < first[st]):  # type: ignore[operator]
                first[st] = f.timestamp
        dated = sorted(
            (s for s, t in first.items() if t is not None),
            key=lambda s: (first[s] or _EPOCH, STAGE_ORDER.index(s)),
        )
        undated = [s for s in STAGE_ORDER if s in first and first[s] is None]
        return [s.value for s in dated + undated]

    def _incident(self, g: CorrelationGroup, stages: list[str]) -> Incident:
        fs = g.findings
        ips = sorted({f.ip for f in fs if f.ip})
        users = sorted({str(f.user) for f in fs if f.user not in _NO_USER})
        stamped = [f.timestamp for f in fs if f.timestamp]
        confs = sorted((f.confidence for f in fs), reverse=True)[:3]
        conf = sum(confs) / len(confs)
        if len(stages) >= 2:
            conf = min(0.97, conf + 0.05 * (len(stages) - 1)) if g.strong else conf * 0.85
        severity = max((f.severity for f in fs), key=lambda s: s.rank)
        vector = self._vector(fs)
        chain = " -> ".join(stages)
        who = ", ".join(ips) if ips else "local activity"
        title = f"Correlated attack chain from {who}" if len(stages) > 1 else f"{fs[0].category.value.replace('_', ' ').title()} from {who}"
        incident = Incident(
            id=stable_id("INC", *sorted(f.id for f in fs)), title=title, severity=severity,
            confidence=round(conf, 2), finding_ids=[f.id for f in fs], ips=ips, users=users, stages=stages,
            start=min(stamped) if stamped else None, end=max(stamped) if stamped else None,
            link_reasons=dict(g.reasons), probable_vector=vector,
            summary=f"{len(fs)} finding(s), stage(s): {chain}. IP(s): {who}.",
        )
        incident.hypotheses = self._hypotheses(fs, incident)
        return incident

    @staticmethod
    def _vector(fs: Sequence[Finding]) -> str | None:
        post = [f.timestamp for f in fs if f.category in (_C.WEBSHELL, _C.UPLOAD_EXEC) and f.timestamp]
        cutoff = min(post) if post else None
        cands = [f for f in fs if f.category in _ENTRY and f.severity.rank >= Severity.MEDIUM.rank
                 and (cutoff is None or f.timestamp is None or f.timestamp <= cutoff)]
        if not cands:
            return None
        pick = min(cands, key=lambda f: (f.timestamp or _EPOCH, -f.severity.rank))
        when = pick.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if pick.timestamp else "unknown time"
        where = pick.metadata.get("request_path") or ""
        return f"{pick.title} from {pick.ip or 'unknown IP'} at {when}{' on ' + where if where else ''} (earliest correlated entry-stage finding; causality not proven)"

    @staticmethod
    def _hypotheses(fs: Sequence[Finding], inc: Incident) -> list[Hypothesis]:
        def ids(*cats: Category) -> list[str]:
            return [f.id for f in fs if f.category in cats]

        label = "HIGH" if inc.confidence >= 0.75 else "MEDIUM" if inc.confidence >= 0.45 else "LOW"
        note = "Causality is inferred from deterministic correlation (same IP/file/time); it is not proven."
        out: list[Hypothesis] = []
        cats = {f.category for f in fs}
        if _C.AUTH_SUCCESS_AFTER_BRUTE_FORCE in cats:
            out.append(Hypothesis("SSH credentials were guessed by brute force: a login succeeded right after a burst of failures.", "deterministic-correlation", label, ids(_C.BRUTE_FORCE, _C.AUTH_SUCCESS_AFTER_BRUTE_FORCE), note=note))
        if cats & {_C.WEBSHELL, _C.UPLOAD_EXEC, _C.WEBSHELL_ACCESS}:
            exploit = sorted({c.value for c in cats & {_C.SQL_INJECTION, _C.REMOTE_CODE_EXECUTION, _C.PATH_TRAVERSAL, _C.XSS}})
            chain = (" after " + "/".join(exploit)) if exploit else ""
            out.append(Hypothesis(f"A script/web shell was placed in a web-accessible location{chain}, then used.", "deterministic-correlation", label, ids(_C.SQL_INJECTION, _C.REMOTE_CODE_EXECUTION, _C.FILE_UPLOAD, _C.UPLOAD_EXEC, _C.WEBSHELL, _C.WEBSHELL_ACCESS), note=note))
        if cats & {_C.PRIVILEGE_ESCALATION, _C.ACCOUNT_CHANGE}:
            out.append(Hypothesis("Privileged activity (sudo/account changes) occurred in the same time frame as the other findings.", "deterministic-correlation", label, ids(_C.PRIVILEGE_ESCALATION, _C.ACCOUNT_CHANGE), note=note))
        if not out:
            out.append(Hypothesis("Attack attempts were observed but no deterministic indicator shows a successful compromise (no web shell, no login after failures).", "deterministic-correlation", label, [f.id for f in fs[:10]], note=note))
        return out
