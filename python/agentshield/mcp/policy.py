"""Config-driven MCP tool allowlist / approval policy.

Human approval UX is out of scope — REQUIRE_APPROVAL is recorded as a finding.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from agentshield.mcp.firewall import FirewallDecision, FirewallResult, ToolAllowlist


@dataclass
class ToolPolicy:
    fail_closed: bool = True
    allowed_tools: list[str] = field(default_factory=list)
    approval_required: list[str] = field(default_factory=list)
    blocked_patterns: list[str] = field(default_factory=list)
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "fail_closed": self.fail_closed,
            "allowed_tools": list(self.allowed_tools),
            "approval_required": list(self.approval_required),
            "blocked_patterns": list(self.blocked_patterns),
            "source": self.source,
        }

    def allowlist(self) -> ToolAllowlist:
        return ToolAllowlist(
            self.allowed_tools,
            self.approval_required,
            fail_closed=self.fail_closed,
        )

    def decide(self, tool_name: str) -> FirewallResult:
        name = (tool_name or "").strip()
        for pattern in self.blocked_patterns:
            try:
                if re.search(pattern, name):
                    return FirewallResult(
                        FirewallDecision.DENY,
                        name,
                        f"blocked_pattern:{pattern}",
                    )
            except re.error:
                if pattern and pattern in name:
                    return FirewallResult(
                        FirewallDecision.DENY,
                        name,
                        f"blocked_pattern:{pattern}",
                    )
        return self.allowlist().decide(name)


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    """Minimal YAML subset for policy files (no external dependency).

    Supports:
      key: value
      key: [a, b]
      key:
        - a
        - b
    """
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(text)
        if isinstance(data, dict):
            return data
    except Exception:
        pass

    result: dict[str, Any] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        if ":" not in stripped:
            i += 1
            continue
        key, _, raw_val = stripped.partition(":")
        key = key.strip()
        raw_val = raw_val.strip()
        if raw_val == "":
            # block list
            items: list[str] = []
            i += 1
            while i < len(lines):
                nxt = lines[i]
                ns = nxt.strip()
                if ns.startswith("- "):
                    items.append(ns[2:].strip().strip("\"'"))
                    i += 1
                    continue
                if ns == "" or ns.startswith("#"):
                    i += 1
                    continue
                break
            result[key] = items
            continue
        if raw_val.startswith("[") and raw_val.endswith("]"):
            inner = raw_val[1:-1].strip()
            result[key] = (
                [p.strip().strip("\"'") for p in inner.split(",") if p.strip()]
                if inner
                else []
            )
        elif raw_val.lower() in ("true", "false"):
            result[key] = raw_val.lower() == "true"
        elif (raw_val.startswith('"') and raw_val.endswith('"')) or (
            raw_val.startswith("'") and raw_val.endswith("'")
        ):
            result[key] = raw_val[1:-1]
        else:
            result[key] = raw_val
        i += 1
    return result


def policy_from_dict(data: Mapping[str, Any], *, source: str = "") -> ToolPolicy:
    return ToolPolicy(
        fail_closed=bool(data.get("fail_closed", True)),
        allowed_tools=list(data.get("allowed_tools") or data.get("allowed") or []),
        approval_required=list(
            data.get("approval_required") or data.get("approve") or []
        ),
        blocked_patterns=list(data.get("blocked_patterns") or []),
        source=source,
    )


def load_policy(path: str | Path | None = None) -> ToolPolicy:
    """Load policy from file; apply env overrides."""
    path_obj: Path | None = Path(path) if path else None
    if path_obj is None:
        env_path = os.environ.get("AGENTSHIELD_POLICY_FILE")
        if env_path:
            path_obj = Path(env_path)

    if path_obj is None:
        policy = ToolPolicy(source="defaults")
    else:
        text = path_obj.read_text(encoding="utf-8")
        if path_obj.suffix.lower() in (".yaml", ".yml"):
            data = _parse_simple_yaml(text)
        else:
            data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError(f"Policy file must be an object: {path_obj}")
        policy = policy_from_dict(data, source=str(path_obj))

    # Env overrides (comma-separated)
    if os.environ.get("AGENTSHIELD_ALLOWED_TOOLS"):
        policy.allowed_tools = [
            n.strip()
            for n in os.environ["AGENTSHIELD_ALLOWED_TOOLS"].split(",")
            if n.strip()
        ]
    if os.environ.get("AGENTSHIELD_APPROVAL_REQUIRED"):
        policy.approval_required = [
            n.strip()
            for n in os.environ["AGENTSHIELD_APPROVAL_REQUIRED"].split(",")
            if n.strip()
        ]
    if os.environ.get("AGENTSHIELD_FAIL_CLOSED") is not None:
        policy.fail_closed = os.environ["AGENTSHIELD_FAIL_CLOSED"].lower() not in (
            "0",
            "false",
            "no",
        )
    return policy
