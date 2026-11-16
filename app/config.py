"""Centralized application settings via Pydantic BaseSettings.

Ref: Settings pattern with lazy singleton accessor.
"""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application-wide configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    project_root: Path = Field(default_factory=lambda: Path.cwd().resolve())
    database_path: Path = Field(default=Path("sample_data/ecommerce.db"))
    documents_path: Path = Field(default=Path("sample_data/documents"))
    environment: str = Field(default="development")

    # Transport
    transport: Literal["stdio", "streamable-http"] = Field(
        default="streamable-http",
    )
    host: str = Field(default="127.0.0.1")
    port: int = Field(default=8000, ge=1024, le=65535)
    auth_token: SecretStr | None = Field(default=None)

    # Resource Bounds
    max_rows: int = Field(default=100, ge=1, le=500)
    max_payload_bytes: int = Field(default=65536, ge=1024, le=1048576)
    query_timeout_seconds: float = Field(default=2.0, gt=0.1, le=10.0)
    max_agent_file_bytes: int = Field(default=1048576, ge=1024, le=10485760)

    # Privacy & Logging
    redact_pii: bool = Field(default=True)
    log_level: str = Field(default="INFO")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Lazy singleton accessor. Override in tests via get_settings.cache_clear()."""
    return Settings()
