"""Runtime configuration for depwatch.

Settings can be overridden with environment variables (prefix ``DEPWATCH_``) or a
``.env`` file, so nothing here is hard-coded into the clients that use it.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CACHE_DIR = PROJECT_ROOT / "data" / "cache"
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "depwatch.duckdb"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="DEPWATCH_", env_file=".env", extra="ignore")

    cache_dir: Path = DEFAULT_CACHE_DIR
    db_path: Path = DEFAULT_DB_PATH
    http_timeout: float = 30.0
    http_max_concurrency: int = 10
    user_agent: str = "depwatch/0.1 (+https://github.com/Tim-tran1406/depwatch)"

    # A GitHub token lifts the API rate limit from 60 to 5000 requests/hour.
    github_token: str | None = Field(default=None)

    depsdev_base_url: str = "https://api.deps.dev/v3"
    osv_base_url: str = "https://api.osv.dev/v1"
    pypi_base_url: str = "https://pypi.org/pypi"
    pypistats_base_url: str = "https://pypistats.org/api"
    github_base_url: str = "https://api.github.com"


settings = Settings()
