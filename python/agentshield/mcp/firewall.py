"""MCP / tool firewall allowlist primitive.

Phase 1 start: deterministic allow / deny / require_approval decisions.
Full IFC and policy DSL land in Phase 2.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Mapping


class FirewallDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass(frozen=True)
class FirewallResult:
    decision: FirewallDecision
    tool_name: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {
            "decision": self.decision.value,
            "tool_name": self.tool_name,
            "reason": self.reason,
        }


class ToolAllowlist:
    """Least-privilege tool gate.

    - `allowed`: tools that may run without extra approval
    - `approval_required`: tools that need human-in-the-loop
    - everything else is denied when `fail_closed=True` (production default)
    """

    def __init__(
        self,
        allowed: Iterable[str] | None = None,
        approval_required: Iterable[str] | None = None,
        *,
        fail_closed: bool = True,
    ) -> None:
        self.allowed = {n.strip() for n in (allowed or []) if n and n.strip()}
        self.approval_required = {
            n.strip() for n in (approval_required or []) if n and n.strip()
        }
        self.fail_closed = fail_closed

    def decide(self, tool_name: str) -> FirewallResult:
        name = (tool_name or "").strip()
        if not name:
            return FirewallResult(
                FirewallDecision.DENY, tool_name="", reason="empty_tool_name"
            )
        if name in self.allowed:
            return FirewallResult(FirewallDecision.ALLOW, name, "allowlisted")
        if name in self.approval_required:
            return FirewallResult(
                FirewallDecision.REQUIRE_APPROVAL, name, "approval_required"
            )
        if self.fail_closed:
            return FirewallResult(FirewallDecision.DENY, name, "not_allowlisted")
        return FirewallResult(
            FirewallDecision.REQUIRE_APPROVAL, name, "fail_open_approval"
        )

    def check_call(self, tool_call: Mapping[str, object]) -> FirewallResult:
        name = str(tool_call.get("name") or tool_call.get("tool") or "")
        return self.decide(name)
