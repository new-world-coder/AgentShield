"""Runtime enforcer — IFC + tool policy with fail-closed / dev-warn modes."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

from agentshield.mcp.firewall import FirewallDecision
from agentshield.runtime.audit_chain import AuditChain
from agentshield.runtime.config import RuntimeMode
from agentshield.runtime.context import ExecutionContext
from agentshield.runtime.policy_dsl import RuntimePolicy
from agentshield.runtime.quarantine import QuarantineStore


class EnforcementDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    WARN = "warn"


@dataclass(frozen=True)
class EnforcementResult:
    decision: EnforcementDecision
    tool_name: str
    reason: str
    rule_id: str = ""
    elapsed_ms: float = 0.0
    labels_in_scope: dict[str, str] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "tool_name": self.tool_name,
            "reason": self.reason,
            "rule_id": self.rule_id,
            "elapsed_ms": self.elapsed_ms,
            "labels_in_scope": self.labels_in_scope,
        }

    @property
    def blocked(self) -> bool:
        return self.decision in (EnforcementDecision.DENY, EnforcementDecision.REQUIRE_APPROVAL)


@dataclass
class RuntimeEnforcer:
    """Evaluate tool calls against labels in scope and runtime policy."""

    policy: RuntimePolicy
    context: ExecutionContext = field(default_factory=ExecutionContext)
    quarantine: QuarantineStore = field(default_factory=QuarantineStore)
    audit: AuditChain | None = None

    def ingest_content(
        self,
        content: str,
        *,
        integrity: str = "untrusted",
        confidentiality: str = "public",
        source: str = "external",
    ) -> str:
        from agentshield.runtime.labels import Confidentiality, FlowLabels, Integrity

        labels = FlowLabels(
            integrity=Integrity.from_string(integrity),
            confidentiality=Confidentiality.from_string(confidentiality),
        )
        visible = content
        if self.policy.quarantine_untrusted and labels.integrity is Integrity.UNTRUSTED:
            visible, labels, ref = self.quarantine.ingest_if_untrusted(
                content, labels, source=source
            )
            if ref and self.audit:
                self.audit.append(
                    "quarantine_store",
                    {"ref_id": ref.ref_id, "source": source, "digest": ref.digest},
                )
        self.context.ingest(content, labels=labels, source=source)
        return visible

    def check_tool_call(self, tool_call: Mapping[str, Any]) -> EnforcementResult:
        start = time.perf_counter()
        name = str(tool_call.get("name") or tool_call.get("tool") or "").strip()
        if not name:
            return self._finalize(
                EnforcementResult(
                    EnforcementDecision.DENY,
                    "",
                    "empty_tool_name",
                    rule_id="runtime.empty",
                ),
                start,
            )

        # Blocked patterns first
        for pattern in self.policy.tool_policy.blocked_patterns:
            try:
                if re.search(pattern, name):
                    return self._finalize(
                        EnforcementResult(
                            EnforcementDecision.DENY,
                            name,
                            f"blocked_pattern:{pattern}",
                            rule_id="tool_policy.blocked",
                        ),
                        start,
                    )
            except re.error:
                if pattern and pattern in name:
                    return self._finalize(
                        EnforcementResult(
                            EnforcementDecision.DENY,
                            name,
                            f"blocked_pattern:{pattern}",
                            rule_id="tool_policy.blocked",
                        ),
                        start,
                    )

        # IFC rules before allowlist — untrusted scope blocks sensitive tools
        for idx, rule in enumerate(self.policy.ifc_rules):
            if not rule.matches(
                has_untrusted=self.context.has_untrusted,
                has_private=self.context.has_private,
            ):
                continue
            if name in rule.deny_tools or self._matches_sensitive(name, rule.deny_tools):
                return self._finalize(
                    EnforcementResult(
                        EnforcementDecision.DENY,
                        name,
                        rule.reason,
                        rule_id=f"ifc.deny.{idx}",
                    ),
                    start,
                )
            if name in rule.require_approval_tools:
                return self._finalize(
                    EnforcementResult(
                        EnforcementDecision.REQUIRE_APPROVAL,
                        name,
                        rule.reason,
                        rule_id=f"ifc.approval.{idx}",
                    ),
                    start,
                )

        if self.context.has_untrusted and name in set(self.policy.sensitive_tools):
            return self._finalize(
                EnforcementResult(
                    EnforcementDecision.DENY,
                    name,
                    "sensitive_tool_with_untrusted_in_scope",
                    rule_id="ifc.sensitive_default",
                ),
                start,
            )

        # Phase 1 tool allowlist (allow / approval / deny)
        fw = self.policy.tool_policy.allowlist().decide(name)
        if fw.decision is FirewallDecision.DENY:
            return self._finalize(
                EnforcementResult(
                    EnforcementDecision.DENY,
                    name,
                    fw.reason,
                    rule_id="tool_policy.deny",
                ),
                start,
            )
        if fw.decision is FirewallDecision.REQUIRE_APPROVAL:
            return self._finalize(
                EnforcementResult(
                    EnforcementDecision.REQUIRE_APPROVAL,
                    name,
                    fw.reason,
                    rule_id="tool_policy.approval",
                ),
                start,
            )

        return self._finalize(
            EnforcementResult(
                EnforcementDecision.ALLOW,
                name,
                "allowed",
                rule_id="runtime.allow",
            ),
            start,
        )

    def _matches_sensitive(self, tool_name: str, patterns: list[str]) -> bool:
        for pattern in patterns:
            if pattern == tool_name:
                return True
            try:
                if re.search(pattern, tool_name):
                    return True
            except re.error:
                continue
        return False

    def _finalize(self, result: EnforcementResult, start: float) -> EnforcementResult:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        labels = self.context.labels_in_scope.to_dict()
        decision = result.decision

        if (
            self.policy.mode is RuntimeMode.DEVELOPMENT
            and result.decision is EnforcementDecision.DENY
        ):
            decision = EnforcementDecision.WARN

        finalized = EnforcementResult(
            decision=decision,
            tool_name=result.tool_name,
            reason=result.reason,
            rule_id=result.rule_id,
            elapsed_ms=round(elapsed_ms, 3),
            labels_in_scope=labels,
        )

        if self.audit:
            self.audit.append(
                "tool_check",
                {
                    "tool": result.tool_name,
                    "decision": finalized.decision.value,
                    "reason": finalized.reason,
                    "rule_id": finalized.rule_id,
                    "elapsed_ms": finalized.elapsed_ms,
                    "labels": labels,
                },
            )

        self.context.record_tool_call(
            {"name": result.tool_name, "decision": finalized.to_dict()}
        )
        return finalized

    def evaluate_trace(self, trace: Mapping[str, Any]) -> list[EnforcementResult]:
        """Replay a trace: ingest content steps then evaluate tool calls."""
        self.context = ExecutionContext.from_trace(dict(trace))
        results: list[EnforcementResult] = []
        for step in trace.get("steps") or []:
            if step.get("type") == "content":
                self.ingest_content(
                    step.get("content") or "",
                    integrity=(step.get("labels") or {}).get("integrity", "untrusted"),
                    confidentiality=(step.get("labels") or {}).get(
                        "confidentiality", "public"
                    ),
                    source=step.get("source") or "external",
                )
            elif step.get("type") == "tool_call":
                call = step.get("call") or step
                results.append(self.check_tool_call(call))
        return results
