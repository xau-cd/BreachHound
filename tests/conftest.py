"""Pytest configuration and shared fixtures."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from breachhound.config.settings import Settings

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"
EXAMPLE = ROOT / "examples" / "sample_investigation"


@pytest.fixture
def settings() -> Settings:
    return Settings(syslog_year=2026)


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture
def example_copy(tmp_path: Path) -> Path:
    """A writable copy of the sample investigation (originals are never touched)."""
    dest = tmp_path / "case"
    shutil.copytree(EXAMPLE, dest)
    return dest
