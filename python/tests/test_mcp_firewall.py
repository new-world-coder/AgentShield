"""Tests for tool allowlist firewall."""

from agentshield.mcp.firewall import FirewallDecision, ToolAllowlist


def test_fail_closed_deny():
    gate = ToolAllowlist(allowed=["get_time"], approval_required=["send_email"])
    assert gate.decide("get_time").decision == FirewallDecision.ALLOW
    assert gate.decide("send_email").decision == FirewallDecision.REQUIRE_APPROVAL
    assert gate.decide("shell").decision == FirewallDecision.DENY


def test_fail_open_requires_approval():
    gate = ToolAllowlist(allowed=["get_time"], fail_closed=False)
    assert gate.decide("unknown").decision == FirewallDecision.REQUIRE_APPROVAL
