"""Runtime configuration — production fail-closed vs development warn mode."""

from __future__ import annotations

from enum import Enum


class RuntimeMode(str, Enum):
    """How policy violations are surfaced at runtime."""

    PRODUCTION = "production"
    DEVELOPMENT = "development"

    @classmethod
    def from_string(cls, value: str | None) -> RuntimeMode:
        if not value:
            return cls.PRODUCTION
        normalized = value.strip().lower()
        if normalized in ("dev", "development", "warn"):
            return cls.DEVELOPMENT
        return cls.PRODUCTION

    @property
    def fail_closed(self) -> bool:
        return self is RuntimeMode.PRODUCTION
