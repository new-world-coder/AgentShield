"""AgentShield Python SDK — MCP firewall + Assure + Runtime."""

__version__ = "0.2.0"

from agentshield.mcp.pin import pin_tool, verify_pin, ToolPin
from agentshield.mcp.scan import scan_tools, ScanReport
from agentshield.mcp.firewall import ToolAllowlist, FirewallDecision
from agentshield.assure.oracles import evaluate_trace
from agentshield.assure.scoring import score_findings, Finding
from agentshield.assure.sarif import findings_to_sarif
from agentshield.runtime.middleware import AgentShieldRuntime
from agentshield.runtime.enforcer import RuntimeEnforcer, EnforcementDecision
from agentshield.runtime.policy_dsl import load_runtime_policy

__all__ = [
    "__version__",
    "pin_tool",
    "verify_pin",
    "ToolPin",
    "scan_tools",
    "ScanReport",
    "ToolAllowlist",
    "FirewallDecision",
    "evaluate_trace",
    "score_findings",
    "Finding",
    "findings_to_sarif",
    "AgentShieldRuntime",
    "RuntimeEnforcer",
    "EnforcementDecision",
    "load_runtime_policy",
]
