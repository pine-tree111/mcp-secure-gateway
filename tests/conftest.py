"""Shared test fixtures for mcp-secure-gateway."""

from collections.abc import Generator
from pathlib import Path

import pytest

from app.config import Settings, get_settings
from sample_data.seed_ecommerce import seed_database


@pytest.fixture
def populated_db(tmp_path: Path) -> Path:
    """Create and seed a temporary SQLite database."""
    db_file = tmp_path / "ecommerce.db"
    seed_database(db_file)
    return db_file


@pytest.fixture
def sample_docs(tmp_path: Path) -> Path:
    """Create sample documents inside a temporary sandbox root."""
    docs_dir = tmp_path / "documents"
    docs_dir.mkdir(parents=True, exist_ok=True)
    (docs_dir / "policies.md").write_text("# Policies\nZero trust.", encoding="utf-8")
    (docs_dir / "notes.txt").write_text(
        "Contact: security@example.com", encoding="utf-8"
    )
    return docs_dir


@pytest.fixture
def test_settings(
    populated_db: Path,
    sample_docs: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[Settings, None, None]:
    """Provide isolated Settings pointing to temporary database and documents."""
    monkeypatch.setenv("DATABASE_PATH", str(populated_db))
    monkeypatch.setenv("DOCUMENTS_PATH", str(sample_docs))
    monkeypatch.setenv("PROJECT_ROOT", str(tmp_path))
    monkeypatch.setenv("ENVIRONMENT", "test")
    get_settings.cache_clear()
    settings = get_settings()
    yield settings
    get_settings.cache_clear()
