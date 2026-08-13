"""Tamper-evident hash-chained audit log for runtime decisions."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping


def _canonical_json(data: Mapping[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hash_payload(payload: str, prev_hash: str) -> str:
    material = f"{prev_hash}\n{payload}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    timestamp: str
    event_type: str
    detail: dict[str, Any]
    prev_hash: str
    entry_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "detail": self.detail,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }


@dataclass
class AuditChain:
    """Append-only JSONL audit chain with verification."""

    path: Path | None = None
    genesis_hash: str = field(default="0" * 64)
    _entries: list[AuditEntry] = field(default_factory=list, repr=False)

    def _last_hash(self) -> str:
        if not self._entries:
            return self.genesis_hash
        return self._entries[-1].entry_hash

    def append(self, event_type: str, detail: Mapping[str, Any]) -> AuditEntry:
        seq = len(self._entries) + 1
        timestamp = datetime.now(timezone.utc).isoformat()
        body = {
            "seq": seq,
            "timestamp": timestamp,
            "event_type": event_type,
            "detail": dict(detail),
        }
        prev_hash = self._last_hash()
        entry_hash = _hash_payload(_canonical_json(body), prev_hash)
        entry = AuditEntry(
            seq=seq,
            timestamp=timestamp,
            event_type=event_type,
            detail=dict(detail),
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
        self._entries.append(entry)
        if self.path:
            self._append_line(entry)
        return entry

    def _append_line(self, entry: AuditEntry) -> None:
        assert self.path is not None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry.to_dict(), ensure_ascii=False) + "\n")

    @classmethod
    def load(cls, path: str | Path, *, genesis_hash: str | None = None) -> AuditChain:
        path_obj = Path(path)
        chain = cls(path=path_obj, genesis_hash=genesis_hash or ("0" * 64))
        if not path_obj.exists():
            return chain
        for line in path_obj.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            raw = json.loads(line)
            chain._entries.append(
                AuditEntry(
                    seq=int(raw["seq"]),
                    timestamp=str(raw["timestamp"]),
                    event_type=str(raw["event_type"]),
                    detail=dict(raw.get("detail") or {}),
                    prev_hash=str(raw["prev_hash"]),
                    entry_hash=str(raw["entry_hash"]),
                )
            )
        return chain

    def verify(self) -> tuple[bool, str]:
        prev = self.genesis_hash
        for entry in self._entries:
            if entry.prev_hash != prev:
                return False, f"prev_hash mismatch at seq {entry.seq}"
            body = {
                "seq": entry.seq,
                "timestamp": entry.timestamp,
                "event_type": entry.event_type,
                "detail": entry.detail,
            }
            expected = _hash_payload(_canonical_json(body), prev)
            if entry.entry_hash != expected:
                return False, f"entry_hash mismatch at seq {entry.seq}"
            prev = entry.entry_hash
        return True, "ok"

    def entries(self) -> Iterable[AuditEntry]:
        return iter(self._entries)
