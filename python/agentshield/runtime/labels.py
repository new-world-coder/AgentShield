"""Information-flow control labels (integrity + confidentiality)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Integrity(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"

    @classmethod
    def from_string(cls, value: str | None) -> Integrity:
        if not value:
            return cls.TRUSTED
        normalized = value.strip().lower()
        if normalized in ("untrusted", "untrust", "external", "tainted"):
            return cls.UNTRUSTED
        return cls.TRUSTED


class Confidentiality(str, Enum):
    PUBLIC = "public"
    PRIVATE = "private"

    @classmethod
    def from_string(cls, value: str | None) -> Confidentiality:
        if not value:
            return cls.PUBLIC
        normalized = value.strip().lower()
        if normalized in ("private", "secret", "confidential", "pii"):
            return cls.PRIVATE
        return cls.PUBLIC


@dataclass(frozen=True)
class FlowLabels:
    """Dual lattice labels for content and derived context."""

    integrity: Integrity = Integrity.TRUSTED
    confidentiality: Confidentiality = Confidentiality.PUBLIC

    def merge(self, other: FlowLabels) -> FlowLabels:
        """Most restrictive combination wins (FIDES-style)."""
        integrity = (
            Integrity.UNTRUSTED
            if self.integrity is Integrity.UNTRUSTED
            or other.integrity is Integrity.UNTRUSTED
            else Integrity.TRUSTED
        )
        confidentiality = (
            Confidentiality.PRIVATE
            if self.confidentiality is Confidentiality.PRIVATE
            or other.confidentiality is Confidentiality.PRIVATE
            else Confidentiality.PUBLIC
        )
        return FlowLabels(integrity=integrity, confidentiality=confidentiality)

    def to_dict(self) -> dict[str, str]:
        return {
            "integrity": self.integrity.value,
            "confidentiality": self.confidentiality.value,
        }

    @classmethod
    def from_dict(cls, data: dict[str, str] | None) -> FlowLabels:
        if not data:
            return cls()
        return cls(
            integrity=Integrity.from_string(data.get("integrity")),
            confidentiality=Confidentiality.from_string(data.get("confidentiality")),
        )
