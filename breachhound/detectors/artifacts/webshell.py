"""Web shell content signatures (read-only, bounded reads)."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from pathlib import Path

from breachhound.core.enums import Severity


@dataclass(frozen=True)
class Signature:
    id: str
    pattern: re.Pattern[str]
    weight: float
    strong: bool
    description: str


def _sig(sid: str, pattern: str, weight: float, strong: bool, desc: str) -> Signature:
    return Signature(sid, re.compile(pattern, re.IGNORECASE), weight, strong, desc)


_REQ = r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b"
SIGNATURES: tuple[Signature, ...] = (
    _sig("PHP-EVAL-DECODE", r"\beval\s*\(\s*@?\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode)\s*\(", 0.40, True, "eval() of decoded payload"),
    _sig("PHP-EVAL-REQUEST", rf"\b(?:eval|assert)\s*\(\s*@?\s*{_REQ}", 0.40, True, "eval()/assert() of request data"),
    _sig("PHP-CMD-REQUEST", rf"\b(?:system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec)\s*\(\s*@?\s*{_REQ}", 0.40, True, "command execution of request data"),
    _sig("PHP-DYN-CALL", rf"{_REQ}\s*\[[^\]]+\]\s*\(", 0.35, True, "function call chosen by request data"),
    _sig("PHP-PREG-E", r"\bpreg_replace\s*\(\s*[\x27\x22]/.*?/[a-z]*e[a-z]*[\x27\x22]\s*,", 0.35, True, "preg_replace with /e modifier"),
    _sig("SHELL-NAME", r"\b(?:c99shell|r57shell|b374k|wso\s+shell|FilesMan|IndoXploit|China\s+Chopper|p0wny)\b", 0.45, True, "known web shell name"),
    _sig("JSP-EXEC", r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(", 0.40, True, "Runtime.exec()"),
    _sig("ASP-EVAL-REQUEST", r"\b(?:eval|execute)\s*\(\s*request", 0.40, True, "eval/execute of request data"),
    _sig("ASP-WSCRIPT", r"WScript\.Shell", 0.30, True, "WScript.Shell"),
    _sig("REVERSE-SHELL", r"\bpty\.spawn\b|/dev/tcp/|bash\s+-i\s*>&", 0.40, True, "reverse shell idiom"),
    _sig("PHP-OBFUSCATION", r"\b(?:base64_decode|gzinflate|str_rot13|gzuncompress)\s*\(", 0.20, False, "decoding function"),
    _sig("PHP-CHR-CHAIN", r"\bchr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(", 0.20, False, "chr() concatenation"),
    _sig("PHP-HEX-BLOB", r"(?:\\x[0-9a-f]{2}){8,}", 0.20, False, "long hex escape sequence"),
    _sig("PHP-VAR-FUNC", r"\$\$[a-z_]\w*\s*\(|\bcreate_function\s*\(", 0.20, False, "variable function / create_function"),
    _sig("PHP-DROPPER", rf"\b(?:file_put_contents|fwrite|fputs)\s*\([^)]*{_REQ}", 0.20, False, "writes request data to disk"),
    _sig("PHP-SILENCE", r"\berror_reporting\s*\(\s*0\s*\)", 0.10, False, "error reporting disabled"),
    _sig("JSP-PARAM", r"request\.getParameter\s*\(", 0.15, False, "request parameter use"),
    _sig("ASP-FSO", r"Scripting\.FileSystemObject", 0.15, False, "FileSystemObject"),
)  # fmt: skip


@dataclass
class SignatureHit:
    signature: Signature
    line: int
    excerpt: str


@dataclass
class WebshellVerdict:
    hits: list[SignatureHit] = field(default_factory=list)
    entropy: float = 0.0
    confidence: float = 0.0
    severity: Severity | None = None

    @property
    def flagged(self) -> bool:
        return self.severity is not None


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts if c)


def scan_text(text: str, entropy: float = 0.0) -> WebshellVerdict:
    """Score a script's content. Needs 1 strong hit, or 2 weak hits, or 1 weak + high entropy."""
    verdict = WebshellVerdict(entropy=entropy)
    seen: set[str] = set()
    for sig in SIGNATURES:
        match = sig.pattern.search(text)
        if match and sig.id not in seen:
            seen.add(sig.id)
            line = text.count("\n", 0, match.start()) + 1
            start = text.rfind("\n", 0, match.start()) + 1
            end = text.find("\n", match.end())
            snippet = text[start : end if end != -1 else None][:300]
            verdict.hits.append(SignatureHit(sig, line, snippet))
    strong = [h for h in verdict.hits if h.signature.strong]
    weak = [h for h in verdict.hits if not h.signature.strong]
    qualifies = bool(strong) or len(weak) >= 2 or (len(weak) == 1 and entropy >= 5.5)
    if not qualifies:
        return verdict
    verdict.confidence = min(0.97, 0.25 + sum(h.signature.weight for h in verdict.hits))
    if verdict.confidence >= 0.80:
        verdict.severity = Severity.CRITICAL
    elif strong:
        verdict.severity = Severity.HIGH
    else:
        verdict.severity = Severity.MEDIUM
    return verdict


def scan_file(path: Path, max_bytes: int) -> WebshellVerdict:
    """Read at most ``max_bytes`` of the file (never executes or modifies it)."""
    with path.open("rb") as handle:
        data = handle.read(max_bytes)
    return scan_text(data.decode("utf-8", "replace"), shannon_entropy(data))
