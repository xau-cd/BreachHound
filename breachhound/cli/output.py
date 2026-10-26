"""Terminal output: Rich when available, plain text fallback."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from typing import Any

from breachhound.core.models import InvestigationResult

try:  # Rich is a declared dependency, but never a hard crash
    from rich import box
    from rich.console import Console
    from rich.markup import escape
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
    from rich.table import Table

    RICH = True
except ImportError:  # pragma: no cover - exercised only without rich installed
    RICH = False

SEVERITY_STYLE = {"CRITICAL": "bold white on red", "HIGH": "bold red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim"}


class UI:
    """Small facade so commands never depend on Rich directly."""

    def __init__(self, quiet: bool = False) -> None:
        self.quiet = quiet
        self._console: Any = Console(highlight=False) if RICH else None

    # -- messages -----------------------------------------------------------------
    def _print(self, text: str, style: str | None = None) -> None:
        if self.quiet:
            return
        if self._console is not None:
            self._console.print(f"[{style}]{escape(text)}[/{style}]" if style else escape(text))
        else:
            print(text)

    def info(self, text: str) -> None:
        self._print(text, "cyan")

    def success(self, text: str) -> None:
        self._print(text, "green")

    def warning(self, text: str) -> None:
        self._print(f"Attention : {text}", "yellow")

    def error(self, text: str) -> None:
        if self._console is not None:
            self._console.print(f"[bold red]Erreur :[/bold red] {escape(text)}")
        else:
            print(f"Erreur : {text}")

    # -- structures -----------------------------------------------------------------
    def table(self, title: str, columns: Sequence[str], rows: Sequence[Sequence[str]], styles: Sequence[str | None] | None = None) -> None:
        if self.quiet:
            return
        if self._console is None:
            print(f"\n{title}")
            for row in rows:
                print("  " + " | ".join(row))
            return
        table = Table(title=title, box=box.SIMPLE_HEAVY, header_style="bold")
        for col in columns:
            table.add_column(col, overflow="fold")
        for i, row in enumerate(rows):
            style = styles[i] if styles else None
            table.add_row(*[escape(str(c)) for c in row], style=style)
        self._console.print(table)

    def panel(self, title: str, body: str, style: str = "cyan") -> None:
        if self.quiet:
            return
        if self._console is None:
            print(f"\n== {title} ==\n{body}")
        else:
            self._console.print(Panel(escape(body), title=title, border_style=style))

    @contextmanager
    def progress(self, total: int) -> Iterator[Callable[[str, int, int], None]]:
        """Yield a callback ``(label, step, total)`` that advances a progress bar."""
        if self.quiet or self._console is None:
            def plain(label: str, step: int, count: int) -> None:
                if not self.quiet:
                    print(f"[{step}/{count}] {label}")

            yield plain
            return
        with Progress(
            SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TaskProgressColumn(),
            console=self._console, transient=True,
        ) as bar:
            task = bar.add_task("Démarrage", total=total)

            def update(label: str, step: int, count: int) -> None:
                bar.update(task, description=escape(label), completed=step - 1, total=count)

            yield update

    def summary(self, result: InvestigationResult, report_paths: Sequence[Any]) -> None:
        risk = result.risk
        assert risk is not None
        style = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}[risk.level.value]
        top = result.incidents[0] if result.incidents else None
        body = (
            f"Sévérité : {risk.level.value}   Score : {risk.score}/100   Confiance : {risk.confidence_level} ({risk.confidence})\n"
            f"Findings : {len(result.findings)}   Incidents corrélés : {len(result.incidents)}   IP : {', '.join(result.ips) or 'aucune'}\n"
            f"Vecteur probable : {(top.probable_vector if top else None) or 'indéterminé'}\n"
            f"Analyse LLM : {result.llm.status}"
            + (f" ({result.llm.error})" if result.llm.status != "ok" and result.llm.error else "")
        )
        self.panel("Résumé de l'investigation", body, style)
        ranked = sorted(result.findings, key=lambda f: (f.severity.rank, f.confidence), reverse=True)[:10]
        if ranked:
            self.table(
                "Principaux findings",
                ["Sévérité", "Catégorie", "IP", "Titre", "Source"],
                [[f.severity.value, f.category.value, f.ip or "-", f.title, f"{(f.source_file or '-').rsplit('/', 1)[-1]}:{f.source_line or '-'}"] for f in ranked],
                [SEVERITY_STYLE[f.severity.value] if f.severity.value in ("CRITICAL",) else None for f in ranked],
            )
        for path in report_paths:
            self.success(f"Rapport : {path}")
