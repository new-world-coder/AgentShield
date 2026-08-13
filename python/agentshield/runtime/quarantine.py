"""Quarantine store — untrusted content never enters the main planner context."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Mapping

from agentshield.runtime.labels import FlowLabels, Integrity


@dataclass(frozen=True)
class QuarantineRef:
    ref_id: str
    digest: str
    placeholder: str

    def to_dict(self) -> dict[str, str]:
        return {
            "ref_id": self.ref_id,
            "digest": self.digest,
            "placeholder": self.placeholder,
        }


class QuarantineStore:
    """Stores raw untrusted bytes; models see opaque references only."""

    def __init__(self, *, prefix: str = "var_untrusted_") -> None:
        self.prefix = prefix
        self._vault: dict[str, str] = {}

    def store(self, content: str, *, source: str = "external") -> QuarantineRef:
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]
        ref_id = f"{self.prefix}{secrets.token_hex(4)}"
        self._vault[ref_id] = content
        placeholder = (
            f"[Quarantined content {ref_id} from {source}; "
            f"digest={digest}. Use quarantine processor to read.]"
        )
        return QuarantineRef(ref_id=ref_id, digest=digest, placeholder=placeholder)

    def resolve(self, ref_id: str) -> str | None:
        return self._vault.get(ref_id)

    def ingest_if_untrusted(
        self,
        content: str,
        labels: FlowLabels,
        *,
        source: str = "external",
    ) -> tuple[str, FlowLabels, QuarantineRef | None]:
        """Return placeholder for untrusted content; pass-through for trusted."""
        if labels.integrity is Integrity.UNTRUSTED:
            ref = self.store(content, source=source)
            return ref.placeholder, labels, ref
        return content, labels, None

    def summary(self) -> Mapping[str, int]:
        return {"stored": len(self._vault)}
