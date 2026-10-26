"""Safe, read-only filesystem helpers (streaming, bounded)."""

from __future__ import annotations

import gzip
import os
from collections.abc import Iterator
from pathlib import Path
from typing import IO

from breachhound.core.constants import DEFAULT_MAX_LINE_LENGTH, PRUNE_DIRS
from breachhound.core.exceptions import FileAccessError


def _open_binary(path: Path) -> IO[bytes]:
    try:
        if path.suffix.lower() == ".gz":
            return gzip.open(path, "rb")  # type: ignore[no-any-return]
        return path.open("rb")
    except PermissionError as exc:
        raise FileAccessError(f"Permission refusée : {path}") from exc
    except FileNotFoundError as exc:
        raise FileAccessError(f"Fichier introuvable : {path}") from exc
    except IsADirectoryError as exc:
        raise FileAccessError(f"Un répertoire a été fourni à la place d'un fichier : {path}") from exc
    except OSError as exc:
        raise FileAccessError(f"Lecture impossible ({exc.strerror or exc}) : {path}") from exc


def iter_lines(
    path: Path, max_line_length: int = DEFAULT_MAX_LINE_LENGTH
) -> Iterator[tuple[int, str, bool]]:
    """Yield ``(line_number, text, truncated)`` without loading the file in memory.

    Invalid encodings are replaced, and lines longer than ``max_line_length`` bytes
    are truncated (the remainder is skipped) so memory stays bounded.
    """
    handle = _open_binary(path)
    try:
        lineno = 0
        while True:
            try:
                raw = handle.readline(max_line_length + 1)
            except (OSError, EOFError) as exc:  # corrupted gzip, I/O error mid-read
                raise FileAccessError(f"Erreur de lecture ({exc}) : {path}") from exc
            if not raw:
                break
            lineno += 1
            truncated = False
            if len(raw) > max_line_length and not raw.endswith(b"\n"):
                truncated = True
                while True:
                    rest = handle.readline(65536)
                    if not rest or rest.endswith(b"\n"):
                        break
                raw = raw[:max_line_length]
            yield lineno, raw.decode("utf-8", "replace").rstrip("\r\n"), truncated
    finally:
        handle.close()


def read_head(path: Path, size: int = 4096) -> bytes:
    """Read the first ``size`` bytes of a file."""
    with path.open("rb") as handle:
        return handle.read(size)


def walk_files(
    root: Path,
    max_files: int,
    errors: list[str],
    prune: frozenset[str] = PRUNE_DIRS,
) -> Iterator[Path]:
    """Yield files under ``root`` without following symlinks.

    Symlinked directories are yielded as entries (not traversed). Problems are
    appended to ``errors`` instead of raising.
    """

    def _onerror(exc: OSError) -> None:
        errors.append(f"{exc.filename}: {exc.strerror or exc}")

    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=_onerror):
        base = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames if d not in prune)
        for d in dirnames:
            if (base / d).is_symlink():
                yield base / d
        for name in sorted(filenames):
            count += 1
            if count > max_files:
                errors.append(f"Limite de {max_files} fichiers atteinte : analyse partielle")
                return
            yield base / name


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def is_within(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True
