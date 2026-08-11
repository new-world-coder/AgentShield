"""AgentBOM generator tests."""

from __future__ import annotations

from agentshield.bom.agentbom import generate_agentbom
from agentshield.mcp.audit import run_mcp_security_audit
from agentshield.mcp.policy import ToolPolicy


def test_agentbom_schema():
    report = run_mcp_security_audit(
        tools=[{"name": "t", "description": "ok", "inputSchema": {}}],
        policy=ToolPolicy(fail_closed=True, allowed_tools=["t"]),
        verify_pins=False,
        agent={"name": "demo-agent", "adapter": "file", "model": "gpt-test"},
    )
    bom = report.agentbom
    assert bom["bomVersion"] == "1.0"
    assert "agentShieldVersion" in bom
    assert "generatedAt" in bom
    assert bom["agent"]["name"] == "demo-agent"
    assert bom["mcpServers"][0]["tools"][0]["name"] == "t"
    assert "findingsSummary" in bom
    assert set(bom["findingsSummary"]) == {"critical", "high", "medium", "low"}


def test_generate_from_audit_report_dict():
    bom = generate_agentbom(
        audit_report={
            "server_id": "s",
            "tools": [{"name": "a"}],
            "firewall_decisions": [{"tool_name": "a", "decision": "allow"}],
            "findings": [],
        },
        agent={"name": "x", "adapter": "stdio", "model": ""},
    )
    assert bom["mcpServers"][0]["id"] == "s"
    assert bom["mcpServers"][0]["tools"][0]["decision"] == "allow"
