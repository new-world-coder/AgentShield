"""MCP schema pin / hash primitives.

Pins the integrity of tool metadata at approval time by hashing
canonical (name + description + input schema). Detects rug pulls
when any of those fields drift (MCP02).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any, Mapping


def _canonical_json(value: Any) -> str:
    """Stable JSON for hashing (sorted keys, no insignificant whitespace)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def tool_fingerprint(tool: Mapping[str, Any]) -> str:
    """Return canonical fingerprint payload for a tool definition."""
    name = tool.get("name", "")
    description = tool.get("description", "")
    # Accept common schema field names used by MCP / function-calling APIs
    schema = (
        tool.get("inputSchema")
        or tool.get("input_schema")
        or tool.get("parameters")
        or {}
    )
    payload = {
        "name": name,
        "description": description,
        "inputSchema": schema,
    }
    return _canonical_json(payload)


def hash_tool(tool: Mapping[str, Any], *, algorithm: str = "sha256") -> str:
    """Compute hex digest of the tool fingerprint."""
    raw = tool_fingerprint(tool).encode("utf-8")
    try:
        h = hashlib.new(algorithm)
    except ValueError as exc:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}") from exc
    h.update(raw)
    return h.hexdigest()


@dataclass(frozen=True)
class ToolPin:
    """Pinned MCP tool metadata."""

    name: str
    algorithm: str
    digest: str
    fingerprint: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, str]) -> "ToolPin":
        return cls(
            name=data["name"],
            algorithm=data.get("algorithm", "sha256"),
            digest=data["digest"],
            fingerprint=data.get("fingerprint", ""),
        )


def pin_tool(tool: Mapping[str, Any], *, algorithm: str = "sha256") -> ToolPin:
    """Create a pin for a tool at approval time."""
    name = str(tool.get("name", "")).strip()
    if not name:
        raise ValueError("Tool must have a non-empty name")
    fingerprint = tool_fingerprint(tool)
    digest = hash_tool(tool, algorithm=algorithm)
    return ToolPin(name=name, algorithm=algorithm, digest=digest, fingerprint=fingerprint)


def verify_pin(
    tool: Mapping[str, Any],
    pin: ToolPin | Mapping[str, str],
) -> tuple[bool, str]:
    """
    Verify a live tool definition against a stored pin.

    Returns (ok, reason). ok=False means reject / re-prompt (rug pull or rename).
    """
    if not isinstance(pin, ToolPin):
        pin = ToolPin.from_dict(pin)

    live_name = str(tool.get("name", "")).strip()
    if live_name != pin.name:
        return False, f"name_mismatch: expected={pin.name!r} live={live_name!r}"

    live_digest = hash_tool(tool, algorithm=pin.algorithm)
    if live_digest != pin.digest:
        return False, f"digest_mismatch: expected={pin.digest} live={live_digest}"

    return True, "ok"
