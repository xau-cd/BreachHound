"""Shared helpers for building synthetic log lines and files."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

T0 = datetime(2026, 10, 12, 10, 0, 0, tzinfo=timezone.utc)
UA = "Mozilla/5.0 (X11; Linux x86_64) Chrome/118.0"


def web_line(target: str, *, ip: str = "198.51.100.23", status: int = 200, offset: int = 0,
             method: str = "GET", ua: str = UA) -> str:
    stamp = (T0 + timedelta(seconds=offset)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{stamp}] "{method} {target} HTTP/1.1" {status} 512 "-" "{ua}"'


def auth_line(msg: str, *, offset: int = 0, proc: str = "sshd", pid: int = 100, host: str = "web01") -> str:
    stamp = (T0 + timedelta(seconds=offset)).strftime("%b %d %H:%M:%S")
    return f"{stamp} {host} {proc}[{pid}]: {msg}"


def failed(ip: str, user: str = "root", offset: int = 0) -> str:
    return auth_line(f"Failed password for {user} from {ip} port 4242 ssh2", offset=offset)


def write_lines(path: Path, lines: list[str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


class StubProvider:
    """Fake LLM provider returning canned text or raising a canned error."""

    name = "stub"
    model = "stub-model"

    def __init__(self, text: str | None = None, error: Exception | None = None) -> None:
        self.text, self.error = text, error

    def complete(self, system: str, prompt: str):  # type: ignore[no-untyped-def]
        from breachhound.llm.base import LLMResponse

        if self.error:
            raise self.error
        return LLMResponse(self.text or "", self.model, self.name)
