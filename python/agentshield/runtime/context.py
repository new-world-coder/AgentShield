"""Execution context — tracks labels in scope for the current agent run."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agentshield.runtime.labels import FlowLabels, Integrity


@dataclass
class ContentRecord:
    ref: str
    labels: FlowLabels
    source: str
    byte_length: int


@dataclass
class ExecutionContext:
    """Accumulates the most restrictive labels seen during a run."""

    labels_in_scope: FlowLabels = field(default_factory=FlowLabels)
    content_records: list[ContentRecord] = field(default_factory=list)
    tool_calls: list[dict[str, Any]] = field(default_factory=list)

    def ingest(
        self,
        content: str,
        *,
        labels: FlowLabels | None = None,
        source: str = "user",
        ref: str | None = None,
    ) -> FlowLabels:
        """Record ingested content and widen context labels."""
        effective = labels or FlowLabels()
        self.labels_in_scope = self.labels_in_scope.merge(effective)
        record = ContentRecord(
            ref=ref or f"content_{len(self.content_records) + 1}",
            labels=effective,
            source=source,
            byte_length=len(content.encode("utf-8")),
        )
        self.content_records.append(record)
        return self.labels_in_scope

    def record_tool_call(self, tool_call: dict[str, Any]) -> None:
        self.tool_calls.append(dict(tool_call))

    @property
    def has_untrusted(self) -> bool:
        return self.labels_in_scope.integrity is Integrity.UNTRUSTED

    @property
    def has_private(self) -> bool:
        from agentshield.runtime.labels import Confidentiality

        return self.labels_in_scope.confidentiality is Confidentiality.PRIVATE

    def to_dict(self) -> dict[str, Any]:
        return {
            "labels_in_scope": self.labels_in_scope.to_dict(),
            "content_records": [
                {
                    "ref": r.ref,
                    "labels": r.labels.to_dict(),
                    "source": r.source,
                    "byte_length": r.byte_length,
                }
                for r in self.content_records
            ],
            "tool_calls": self.tool_calls,
        }

    @classmethod
    def from_trace(cls, trace: dict[str, Any]) -> ExecutionContext:
        """Rebuild context from a serialized execution trace."""
        ctx = cls()
        for step in trace.get("steps") or []:
            if step.get("type") == "content":
                ctx.ingest(
                    step.get("content") or "",
                    labels=FlowLabels.from_dict(step.get("labels")),
                    source=step.get("source") or "unknown",
                    ref=step.get("ref"),
                )
            elif step.get("type") == "tool_call":
                ctx.record_tool_call(step.get("call") or step)
        if trace.get("labels_in_scope"):
            ctx.labels_in_scope = FlowLabels.from_dict(trace["labels_in_scope"])
        return ctx
