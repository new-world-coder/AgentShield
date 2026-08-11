"""AgentShield Python SDK — MCP firewall + Assure primitives."""

__version__ = "0.1.0"

from agentshield.mcp.pin import pin_tool, verify_pin, ToolPin
from agentshield.mcp.scan import scan_tools, ScanReport
from agentshield.mcp.firewall import ToolAllowlist, FirewallDecision
from agentshield.assure.oracles import evaluate_trace, OracleResult
from agentshield.assure.scoring import score_findings, Finding
from agentshield.assure.sarif import findings_to_sarif

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
    "OracleResult",
    "score_findings",
    "Finding",
    "findings_to_sarif",
]
