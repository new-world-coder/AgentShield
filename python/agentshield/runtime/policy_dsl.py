"""Runtime policy DSL — extends Phase 1 tool policy with IFC rules."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from agentshield.mcp.policy import ToolPolicy, _parse_simple_yaml, load_policy, policy_from_dict
from agentshield.runtime.config import RuntimeMode
from agentshield.runtime.labels import Confidentiality, Integrity


@dataclass
class IfcRule:
    """When labels in scope match, deny or require approval for listed tools."""

    when: dict[str, str] = field(default_factory=dict)
    deny_tools: list[str] = field(default_factory=list)
    require_approval_tools: list[str] = field(default_factory=list)
    reason: str = "ifc_rule"

    def matches(self, *, has_untrusted: bool, has_private: bool) -> bool:
        if not self.when:
            return False
        for key, expected in self.when.items():
            normalized = expected.strip().lower()
            if key in ("integrity_in_scope", "integrity"):
                actual = "untrusted" if has_untrusted else "trusted"
                if actual != normalized:
                    return False
            elif key in ("confidentiality_in_scope", "confidentiality"):
                actual = "private" if has_private else "public"
                if actual != normalized:
                    return False
            else:
                return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "when": dict(self.when),
            "deny_tools": list(self.deny_tools),
            "require_approval_tools": list(self.require_approval_tools),
            "reason": self.reason,
        }


@dataclass
class RuntimePolicy:
    """Combined tool allowlist + information-flow rules."""

    mode: RuntimeMode = RuntimeMode.PRODUCTION
    tool_policy: ToolPolicy = field(default_factory=ToolPolicy)
    ifc_rules: list[IfcRule] = field(default_factory=list)
    sensitive_tools: list[str] = field(default_factory=list)
    quarantine_untrusted: bool = True
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode.value,
            "tool_policy": self.tool_policy.to_dict(),
            "ifc_rules": [r.to_dict() for r in self.ifc_rules],
            "sensitive_tools": list(self.sensitive_tools),
            "quarantine_untrusted": self.quarantine_untrusted,
            "source": self.source,
        }


def _parse_ifc_rules(raw: list[Any] | None) -> list[IfcRule]:
    rules: list[IfcRule] = []
    for item in raw or []:
        if not isinstance(item, dict):
            continue
        rules.append(
            IfcRule(
                when=dict(item.get("when") or {}),
                deny_tools=list(item.get("deny_tools") or []),
                require_approval_tools=list(
                    item.get("require_approval_tools") or item.get("approve_tools") or []
                ),
                reason=str(item.get("reason") or "ifc_rule"),
            )
        )
    return rules


def runtime_policy_from_dict(data: Mapping[str, Any], *, source: str = "") -> RuntimePolicy:
    mode = RuntimeMode.from_string(str(data.get("mode") or "production"))
    tool_block = data.get("tool_policy")
    if isinstance(tool_block, dict):
        tool_policy = policy_from_dict(tool_block, source=source)
    else:
        tool_policy = policy_from_dict(data, source=source)
    if "fail_closed" in data and "tool_policy" not in data:
        tool_policy.fail_closed = bool(data["fail_closed"])
    if mode is RuntimeMode.PRODUCTION:
        tool_policy.fail_closed = True
    return RuntimePolicy(
        mode=mode,
        tool_policy=tool_policy,
        ifc_rules=_parse_ifc_rules(data.get("ifc_rules")),  # type: ignore[arg-type]
        sensitive_tools=list(data.get("sensitive_tools") or []),
        quarantine_untrusted=bool(data.get("quarantine_untrusted", True)),
        source=source,
    )


def load_runtime_policy(path: str | Path | None = None) -> RuntimePolicy:
    """Load runtime policy; falls back to tool-only policy shape."""
    path_obj: Path | None = Path(path) if path else None
    if path_obj is None:
        env_path = os.environ.get("AGENTSHIELD_RUNTIME_POLICY_FILE")
        if env_path:
            path_obj = Path(env_path)

    if path_obj is None:
        return RuntimePolicy(tool_policy=load_policy(None), source="defaults")

    text = path_obj.read_text(encoding="utf-8")
    if path_obj.suffix.lower() in (".yaml", ".yml"):
        data = _parse_simple_yaml(text)
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"Runtime policy must be an object: {path_obj}")
    return runtime_policy_from_dict(data, source=str(path_obj))


def compile_policy_ast(policy: RuntimePolicy) -> dict[str, Any]:
    """Lightweight AST for future CEL/Rego compiler (Phase 2+)."""
    return {
        "version": "1.0",
        "mode": policy.mode.value,
        "rules": [
            {
                "type": "ifc",
                "when": rule.when,
                "effect": "deny" if rule.deny_tools else "require_approval",
                "tools": rule.deny_tools or rule.require_approval_tools,
            }
            for rule in policy.ifc_rules
        ],
        "tool_policy": policy.tool_policy.to_dict(),
        "sensitive_tools": policy.sensitive_tools,
    }
