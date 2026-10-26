"""Enumerations shared across the code base."""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    """Finding / incident severity."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self.value]

    @classmethod
    def from_str(cls, value: str) -> Severity:
        try:
            return cls(value.strip().upper())
        except ValueError as exc:
            raise ValueError(f"Unknown severity: {value!r}") from exc


_SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class RiskLevel(str, Enum):
    """Overall risk level produced by the risk engine."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return ("LOW", "MEDIUM", "HIGH", "CRITICAL").index(self.value)


class SourceType(str, Enum):
    WEB = "web"
    AUTH = "auth"
    ARTIFACT = "artifact"


class Category(str, Enum):
    """Technical category of a finding."""

    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    REMOTE_CODE_EXECUTION = "REMOTE_CODE_EXECUTION"
    SCANNER = "SCANNER"
    RECON = "RECON"
    FILE_UPLOAD = "FILE_UPLOAD"
    BRUTE_FORCE = "BRUTE_FORCE"
    AUTH_SUCCESS_AFTER_BRUTE_FORCE = "AUTH_SUCCESS_AFTER_BRUTE_FORCE"
    CONNECTION_BURST = "CONNECTION_BURST"
    ROOT_LOGIN = "ROOT_LOGIN"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    ACCOUNT_CHANGE = "ACCOUNT_CHANGE"
    WEBSHELL = "WEBSHELL"
    WEBSHELL_ACCESS = "WEBSHELL_ACCESS"
    UPLOAD_EXEC = "UPLOAD_EXEC"
    EXTENSION_MISMATCH = "EXTENSION_MISMATCH"
    HIDDEN_FILE = "HIDDEN_FILE"
    RECENT_MODIFICATION = "RECENT_MODIFICATION"
    INTEGRITY = "INTEGRITY"
    SUSPICIOUS_FILE = "SUSPICIOUS_FILE"
    PERMISSIONS = "PERMISSIONS"
    IOC_HASH_MATCH = "IOC_HASH_MATCH"


class Stage(str, Enum):
    """Simplified kill-chain stages (definition order = canonical order)."""

    RECONNAISSANCE = "reconnaissance"
    CREDENTIAL_ACCESS = "credential_access"
    EXPLOITATION = "exploitation"
    INITIAL_ACCESS = "initial_access"
    UPLOAD = "upload"
    WEBSHELL = "webshell_persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    TAMPERING = "tampering"


STAGE_ORDER: tuple[Stage, ...] = tuple(Stage)

_C = Category
_S = Stage
STAGE_BY_CATEGORY: dict[Category, Stage] = {
    _C.SCANNER: _S.RECONNAISSANCE,
    _C.RECON: _S.RECONNAISSANCE,
    _C.CONNECTION_BURST: _S.RECONNAISSANCE,
    _C.BRUTE_FORCE: _S.CREDENTIAL_ACCESS,
    _C.SQL_INJECTION: _S.EXPLOITATION,
    _C.XSS: _S.EXPLOITATION,
    _C.PATH_TRAVERSAL: _S.EXPLOITATION,
    _C.REMOTE_CODE_EXECUTION: _S.EXPLOITATION,
    _C.AUTH_SUCCESS_AFTER_BRUTE_FORCE: _S.INITIAL_ACCESS,
    _C.FILE_UPLOAD: _S.UPLOAD,
    _C.UPLOAD_EXEC: _S.UPLOAD,
    _C.EXTENSION_MISMATCH: _S.UPLOAD,
    _C.WEBSHELL: _S.WEBSHELL,
    _C.WEBSHELL_ACCESS: _S.WEBSHELL,
    _C.IOC_HASH_MATCH: _S.WEBSHELL,
    _C.ROOT_LOGIN: _S.PRIVILEGE_ESCALATION,
    _C.PRIVILEGE_ESCALATION: _S.PRIVILEGE_ESCALATION,
    _C.ACCOUNT_CHANGE: _S.PRIVILEGE_ESCALATION,
    _C.INTEGRITY: _S.TAMPERING,
    _C.SUSPICIOUS_FILE: _S.TAMPERING,
    _C.HIDDEN_FILE: _S.TAMPERING,
    _C.RECENT_MODIFICATION: _S.TAMPERING,
    _C.PERMISSIONS: _S.TAMPERING,
}


def stage_of(category: Category) -> Stage:
    """Return the kill-chain stage associated with a category."""
    return STAGE_BY_CATEGORY[category]


def confidence_label(value: float) -> str:
    """Map a 0..1 confidence to an explicit label."""
    if value >= 0.75:
        return "HIGH"
    if value >= 0.45:
        return "MEDIUM"
    return "LOW"
