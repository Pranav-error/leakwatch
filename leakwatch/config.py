"""Environment-driven configuration.

All tunables live here so the rest of the code never reads os.environ directly.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

try:  # optional: load a local .env if python-dotenv is installed
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # pragma: no cover - dotenv is a convenience, not a requirement
    pass


def _csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    github_token: str | None = field(
        default_factory=lambda: os.environ.get("GITHUB_TOKEN") or None
    )
    db_path: str = field(
        default_factory=lambda: os.environ.get("LEAKWATCH_DB", "leakwatch.db")
    )
    code_search_interval: int = field(
        default_factory=lambda: int(os.environ.get("CODE_SEARCH_INTERVAL", "900"))
    )
    events_interval: int = field(
        default_factory=lambda: int(os.environ.get("EVENTS_INTERVAL", "60"))
    )
    provider_allowlist: list[str] = field(
        default_factory=lambda: _csv(os.environ.get("PROVIDER_ALLOWLIST"))
    )
    # Verification means USING someone else's credential. Off by default; there is
    # no live implementation in v1 regardless of this flag.
    enable_verification: bool = field(
        default_factory=lambda: os.environ.get("ENABLE_VERIFICATION", "false").lower()
        == "true"
    )

    @property
    def db_url(self) -> str:
        return f"sqlite:///{self.db_path}"


settings = Settings()
