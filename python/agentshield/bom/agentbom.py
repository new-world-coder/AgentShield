"""AgentBOM v1 — inventory of agent + MCP attack surface."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from agentshield import __version__


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _policy_hash(policy: Mapping[str, Any] | None) -> str:
    if not policy:
        return ""
    raw = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def generate_agentbom(
    *,
    audit: Any = None,
    agent: Mapping[str, Any] | None = None,
    policy: Any = None,
    registry: Any = None,
    server: Any = None,
    audit_report: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build AgentBOM v1 JSON from an audit report and optional metadata."""
    data: dict[str, Any]
    if audit_report is not None:
        data = dict(audit_report)
    elif audit is not None and hasattr(audit, "to_dict"):
        data = audit.to_dict()
    elif isinstance(audit, Mapping):
        data = dict(audit)
    else:
        data = {}

    server_id = str(
        getattr(server, "id", None)
        or data.get("server_id")
        or (agent or {}).get("name")
        or "default"
    )
    transport = str(getattr(server, "transport", None) or data.get("transport") or "file")

    decisions = {
        d.get("tool_name"): d.get("decision")
        for d in (data.get("firewall_decisions") or [])
        if isinstance(d, Mapping)
    }

    pin_by_name: dict[str, str] = {}
    if registry is not None and hasattr(registry, "list_pins"):
        for rec in registry.list_pins(server_id):
            pin_by_name[rec.tool_name] = rec.pin_hash

    tools_out = []
    for tool in data.get("tools") or []:
        if not isinstance(tool, Mapping):
            continue
        name = str(tool.get("name") or "")
        tools_out.append(
            {
                "name": name,
                "pinHash": pin_by_name.get(name, ""),
                "decision": decisions.get(name, "unknown"),
            }
        )

    pol_dict: dict[str, Any] = {}
    pol_path = ""
    if policy is not None:
        if hasattr(policy, "to_dict"):
            pol_dict = policy.to_dict()
            pol_path = str(getattr(policy, "source", "") or "")
        elif isinstance(policy, Mapping):
            pol_dict = dict(policy)
            pol_path = str(policy.get("source") or "")

    findings = data.get("findings") or []
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        if isinstance(f, Mapping) and f.get("passed"):
            continue
        sev = str((f or {}).get("severity") or "Low").lower()
        if sev in summary:
            summary[sev] += 1

    agent_meta = {
        "name": (agent or {}).get("name") or server_id,
        "adapter": (agent or {}).get("adapter") or transport,
        "model": (agent or {}).get("model") or "",
    }

    return {
        "bomVersion": "1.0",
        "agentShieldVersion": __version__,
        "generatedAt": _utc_now(),
        "agent": agent_meta,
        "mcpServers": [
            {
                "id": server_id,
                "transport": transport,
                "tools": tools_out,
            }
        ],
        "policies": (
            [
                {
                    "name": Path(pol_path).name if pol_path else "policy",
                    "path": pol_path,
                    "hash": _policy_hash(pol_dict),
                }
            ]
            if pol_dict or pol_path
            else []
        ),
        "findingsSummary": summary,
    }


def load_audit_report(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))
