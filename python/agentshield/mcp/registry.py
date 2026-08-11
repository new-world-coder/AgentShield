"""Persistent MCP pin registry with rug-pull / schema-drift detection.

Default storage: project-local `.agentshield/pins.json` or
`~/.agentshield/pins.json` (override via path / AGENTSHIELD_PINS_FILE).
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from agentshield.mcp.pin import hash_tool, pin_tool, tool_fingerprint


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class PinRecord:
    server_id: str
    tool_name: str
    pin_hash: str
    pinned_at: str
    algorithm: str = "sha256"
    canonical_snapshot: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "PinRecord":
        return cls(
            server_id=str(data.get("server_id") or "default"),
            tool_name=str(data["tool_name"] if "tool_name" in data else data["name"]),
            pin_hash=str(data.get("pin_hash") or data.get("digest") or ""),
            pinned_at=str(data.get("pinned_at") or _utc_now()),
            algorithm=str(data.get("algorithm") or "sha256"),
            canonical_snapshot=str(data.get("canonical_snapshot") or data.get("fingerprint") or ""),
        )


@dataclass
class DriftFinding:
    server_id: str
    tool_name: str
    rule_id: str
    severity: str
    message: str
    expected_hash: str = ""
    live_hash: str = ""
    taxonomy: str = "MCP02"

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def default_pins_path(*, prefer_project: bool = True) -> Path:
    env = os.environ.get("AGENTSHIELD_PINS_FILE")
    if env:
        return Path(env)
    project = Path.cwd() / ".agentshield" / "pins.json"
    if prefer_project and (project.parent.exists() or prefer_project):
        return project
    return Path.home() / ".agentshield" / "pins.json"


class PinRegistry:
    """JSON-file backed pin store."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else default_pins_path()
        self._pins: dict[str, PinRecord] = {}
        self.load()

    @staticmethod
    def _key(server_id: str, tool_name: str) -> str:
        return f"{server_id}::{tool_name}"

    def load(self) -> None:
        if not self.path.exists():
            self._pins = {}
            return
        data = json.loads(self.path.read_text(encoding="utf-8"))
        records = data.get("pins", data if isinstance(data, list) else [])
        self._pins = {}
        for item in records:
            rec = PinRecord.from_dict(item)
            self._pins[self._key(rec.server_id, rec.tool_name)] = rec

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "updated_at": _utc_now(),
            "pins": [p.to_dict() for p in sorted(self._pins.values(), key=lambda r: (r.server_id, r.tool_name))],
        }
        self.path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    def list_pins(self, server_id: str | None = None) -> list[PinRecord]:
        pins = list(self._pins.values())
        if server_id is not None:
            pins = [p for p in pins if p.server_id == server_id]
        return sorted(pins, key=lambda r: (r.server_id, r.tool_name))

    def add_tool(
        self,
        tool: Mapping[str, Any],
        *,
        server_id: str = "default",
        algorithm: str = "sha256",
    ) -> PinRecord:
        pin = pin_tool(tool, algorithm=algorithm)
        record = PinRecord(
            server_id=server_id,
            tool_name=pin.name,
            pin_hash=pin.digest,
            pinned_at=_utc_now(),
            algorithm=pin.algorithm,
            canonical_snapshot=pin.fingerprint or tool_fingerprint(tool),
        )
        self._pins[self._key(server_id, pin.name)] = record
        return record

    def pin_all(
        self,
        tools: Sequence[Mapping[str, Any]],
        *,
        server_id: str = "default",
        algorithm: str = "sha256",
        persist: bool = True,
    ) -> list[PinRecord]:
        records = [
            self.add_tool(t, server_id=server_id, algorithm=algorithm) for t in tools
        ]
        if persist:
            self.save()
        return records

    def verify_tools(
        self,
        tools: Sequence[Mapping[str, Any]],
        *,
        server_id: str = "default",
    ) -> list[DriftFinding]:
        findings: list[DriftFinding] = []
        live_names: set[str] = set()

        for tool in tools:
            name = str(tool.get("name") or "").strip()
            if not name:
                continue
            live_names.add(name)
            key = self._key(server_id, name)
            stored = self._pins.get(key)
            live_hash = hash_tool(tool, algorithm=(stored.algorithm if stored else "sha256"))

            if stored is None:
                findings.append(
                    DriftFinding(
                        server_id=server_id,
                        tool_name=name,
                        rule_id="unpinned_tool",
                        severity="High",
                        message=f"Tool {name!r} has no stored pin",
                        live_hash=live_hash,
                        taxonomy="MCP02",
                    )
                )
                continue

            if live_hash != stored.pin_hash:
                findings.append(
                    DriftFinding(
                        server_id=server_id,
                        tool_name=name,
                        rule_id="schema_drift",
                        severity="Critical",
                        message=(
                            f"Rug pull / schema drift for {name!r}: "
                            f"pin {stored.pin_hash[:12]}… ≠ live {live_hash[:12]}…"
                        ),
                        expected_hash=stored.pin_hash,
                        live_hash=live_hash,
                        taxonomy="MCP02",
                    )
                )

        # Missing previously pinned tools
        for rec in self.list_pins(server_id):
            if rec.tool_name not in live_names:
                findings.append(
                    DriftFinding(
                        server_id=server_id,
                        tool_name=rec.tool_name,
                        rule_id="missing_pinned_tool",
                        severity="High",
                        message=f"Pinned tool {rec.tool_name!r} missing from live tools/list",
                        expected_hash=rec.pin_hash,
                        taxonomy="MCP02",
                    )
                )

        return findings
