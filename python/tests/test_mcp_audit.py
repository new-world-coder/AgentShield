"""Policy + integrated MCP audit tests."""

from __future__ import annotations

import json
from pathlib import Path

from agentshield.mcp.audit import (
    audit_to_sarif,
    fails_severity_threshold,
    run_mcp_security_audit,
)
from agentshield.mcp.firewall import FirewallDecision
from agentshield.mcp.policy import ToolPolicy, load_policy, policy_from_dict
from agentshield.mcp.registry import PinRegistry

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
POISONED = EXAMPLES / "tools_poisoned.json"
TOOL = EXAMPLES / "tool.json"


def test_policy_fail_closed_deny(tmp_path):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "fail_closed: true\nallowed_tools: []\napproval_required: []\n",
        encoding="utf-8",
    )
    pol = load_policy(policy_path)
    result = pol.decide("search_docs")
    assert result.decision == FirewallDecision.DENY


def test_policy_blocked_pattern():
    pol = policy_from_dict(
        {
            "fail_closed": False,
            "allowed_tools": ["exec_shell"],
            "blocked_patterns": ["^exec_"],
        }
    )
    assert pol.decide("exec_shell").decision == FirewallDecision.DENY


def test_audit_poisoned_exits_findings(tmp_path):
    policy = ToolPolicy(fail_closed=True, allowed_tools=["search_docs"])
    reg = PinRegistry(tmp_path / "pins.json")
    # pin only benign first tool shape
    benign = json.loads(TOOL.read_text(encoding="utf-8"))
    reg.pin_all([benign], server_id="file")

    report = run_mcp_security_audit(
        str(POISONED),
        policy=policy,
        registry=reg,
        include_unpinned=True,
    )
    assert report.ok is False
    assert report.scan_findings
    assert any(d["decision"] != "allow" for d in report.firewall_decisions)
    sarif = audit_to_sarif(report)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]
    assert fails_severity_threshold(report, "high")
    assert report.agentbom is not None
    assert report.agentbom["bomVersion"] == "1.0"


def test_audit_allowlist_and_approval(tmp_path):
    tools = [
        {"name": "read_file", "description": "read", "inputSchema": {}},
        {"name": "write_file", "description": "write", "inputSchema": {}},
        {"name": "shell", "description": "exec", "inputSchema": {}},
    ]
    policy = ToolPolicy(
        fail_closed=True,
        allowed_tools=["read_file"],
        approval_required=["write_file"],
    )
    report = run_mcp_security_audit(
        tools=tools,
        policy=policy,
        pins_path=str(tmp_path / "pins.json"),
        verify_pins=False,
    )
    by_name = {d["tool_name"]: d["decision"] for d in report.firewall_decisions}
    assert by_name["read_file"] == "allow"
    assert by_name["write_file"] == "require_approval"
    assert by_name["shell"] == "deny"
    assert any(f["rule_id"] == "require_approval" for f in report.findings)
