"""High-level runtime middleware facade for agent hosts."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from agentshield.runtime.audit_chain import AuditChain
from agentshield.runtime.enforcer import EnforcementResult, RuntimeEnforcer
from agentshield.runtime.policy_dsl import RuntimePolicy, load_runtime_policy


class AgentShieldRuntime:
    """Drop-in runtime gate: quarantine → IFC → tool policy → audit chain."""

    def __init__(
        self,
        policy: RuntimePolicy | str | Path | None = None,
        *,
        audit_path: str | Path | None = None,
    ) -> None:
        if isinstance(policy, (str, Path)):
            self.policy = load_runtime_policy(policy)
        elif isinstance(policy, RuntimePolicy):
            self.policy = policy
        else:
            self.policy = load_runtime_policy(None)
        audit = AuditChain.load(audit_path) if audit_path else AuditChain()
        if audit_path:
            audit.path = Path(audit_path)
        self.enforcer = RuntimeEnforcer(
            policy=self.policy,
            audit=audit if audit_path else None,
        )

    def on_untrusted_content(self, content: str, *, source: str = "external") -> str:
        return self.enforcer.ingest_content(
            content,
            integrity="untrusted",
            confidentiality="public",
            source=source,
        )

    def before_tool_call(self, tool_call: Mapping[str, Any]) -> EnforcementResult:
        return self.enforcer.check_tool_call(tool_call)

    def after_tool_call(
        self, tool_call: Mapping[str, Any], result: Mapping[str, Any]
    ) -> None:
        if self.enforcer.audit:
            self.enforcer.audit.append(
                "tool_result",
                {
                    "tool": str(tool_call.get("name") or tool_call.get("tool") or ""),
                    "ok": bool(result.get("ok", True)),
                },
            )

    def replay_trace(self, trace: Mapping[str, Any]) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self.enforcer.evaluate_trace(trace)]

    def verify_audit_chain(self) -> tuple[bool, str]:
        if not self.enforcer.audit:
            return True, "no_audit_chain"
        return self.enforcer.audit.verify()
