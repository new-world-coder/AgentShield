"""Integrated MCP security audit pipeline.

adapter → scan → pin verify → allowlist/policy check → score + SARIF.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from agentshield.assure.sarif import findings_to_sarif
from agentshield.assure.scoring import Finding, score_findings
from agentshield.mcp.adapter import (
    AdapterError,
    ServerConfig,
    ToolDefinition,
    list_tools,
)
from agentshield.mcp.firewall import FirewallDecision
from agentshield.mcp.policy import ToolPolicy, load_policy
from agentshield.mcp.registry import DriftFinding, PinRegistry
from agentshield.mcp.scan import ScanFinding, scan_tools


SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


@dataclass
class AuditReport:
    server_id: str
    tools: list[dict[str, Any]] = field(default_factory=list)
    scan_findings: list[dict[str, Any]] = field(default_factory=list)
    drift_findings: list[dict[str, Any]] = field(default_factory=list)
    firewall_decisions: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    score: int = 0
    severity: str = "Low"
    summary: str = ""
    ok: bool = True
    error: dict[str, str] | None = None
    agentbom: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "server_id": self.server_id,
            "tools": self.tools,
            "scan_findings": self.scan_findings,
            "drift_findings": self.drift_findings,
            "firewall_decisions": self.firewall_decisions,
            "findings": self.findings,
            "score": self.score,
            "severity": self.severity,
            "summary": self.summary,
            "ok": self.ok,
            "error": self.error,
            "agentbom": self.agentbom,
        }


def _scan_to_finding(f: ScanFinding) -> Finding:
    impact = (
        "supply_chain_integrity"
        if f.severity in ("Critical", "High")
        else "hygiene"
    )
    return Finding(
        rule_id=f.rule_id,
        message=f.message,
        impact=impact,
        confidence=0.85,
        severity=f.severity,
        taxonomy=[f.taxonomy] if f.taxonomy else [],
        evidence=f.evidence,
        passed=False,
    )


def _drift_to_finding(f: DriftFinding) -> Finding:
    return Finding(
        rule_id=f.rule_id,
        message=f.message,
        impact="supply_chain_integrity",
        confidence=0.99 if f.rule_id == "schema_drift" else 0.9,
        severity=f.severity,
        taxonomy=[f.taxonomy],
        evidence=f"{f.expected_hash}|{f.live_hash}",
        passed=False,
    )


def _decision_to_finding(decision: Mapping[str, str]) -> Finding | None:
    d = decision.get("decision")
    if d == FirewallDecision.ALLOW.value:
        return None
    if d == FirewallDecision.REQUIRE_APPROVAL.value:
        return Finding(
            rule_id="require_approval",
            message=f"Tool {decision.get('tool_name')!r} requires human approval",
            impact="excessive_agency",
            confidence=0.9,
            severity="High",
            taxonomy=["MCP05"],
            evidence=decision.get("reason", ""),
            passed=False,
        )
    return Finding(
        rule_id="firewall_deny",
        message=f"Tool {decision.get('tool_name')!r} denied by policy",
        impact="excessive_agency",
        confidence=0.95,
        severity="High",
        taxonomy=["MCP05"],
        evidence=decision.get("reason", ""),
        passed=False,
    )


def run_mcp_security_audit(
    config: ServerConfig | Mapping[str, Any] | str | None = None,
    *,
    tools: Sequence[Mapping[str, Any]] | None = None,
    policy: ToolPolicy | Mapping[str, Any] | str | None = None,
    registry: PinRegistry | None = None,
    pins_path: str | None = None,
    verify_pins: bool = True,
    include_unpinned: bool = True,
    build_bom: bool = True,
    agent: Mapping[str, Any] | None = None,
) -> AuditReport:
    """Run adapter → scan → pin verify → allowlist and return AuditReport."""
    from agentshield.bom.agentbom import generate_agentbom

    if isinstance(config, Mapping):
        server = ServerConfig.from_dict(config)
    elif isinstance(config, ServerConfig):
        server = config
    elif isinstance(config, str):
        server = ServerConfig(id="file", transport="file", path=config)
    else:
        server = ServerConfig(id="inline", transport="file")

    report = AuditReport(server_id=server.id)

    # Resolve tools
    resolved: list[ToolDefinition] = []
    try:
        if tools is not None:
            from agentshield.mcp.adapter import tools_from_payload

            resolved = tools_from_payload(list(tools))
        elif server.path or server.command or server.url:
            resolved = list_tools(server)
        elif isinstance(config, str):
            resolved = list_tools(config)
        else:
            raise AdapterError("No tools source provided", code="invalid_config")
    except AdapterError as exc:
        report.ok = False
        report.error = exc.to_dict()
        report.severity = "Critical"
        report.summary = exc.message
        return report

    tool_dicts = [t.to_dict() for t in resolved]
    report.tools = tool_dicts

    # Policy
    if isinstance(policy, ToolPolicy):
        pol = policy
    elif isinstance(policy, Mapping):
        from agentshield.mcp.policy import policy_from_dict

        pol = policy_from_dict(policy)
    elif isinstance(policy, str):
        pol = load_policy(policy)
    else:
        pol = load_policy(None)

    # Scan
    scan_report = scan_tools(tool_dicts)
    report.scan_findings = [f.to_dict() for f in scan_report.findings]

    # Pin verify
    reg = registry or PinRegistry(pins_path)
    drift: list[DriftFinding] = []
    if verify_pins:
        drift = reg.verify_tools(tool_dicts, server_id=server.id)
        if not include_unpinned:
            drift = [d for d in drift if d.rule_id != "unpinned_tool"]
    report.drift_findings = [d.to_dict() for d in drift]

    # Firewall / policy
    decisions = []
    for t in tool_dicts:
        result = pol.decide(str(t.get("name") or ""))
        decisions.append(result.to_dict())
    report.firewall_decisions = decisions

    # Aggregate findings
    findings: list[Finding] = [_scan_to_finding(f) for f in scan_report.findings]
    findings.extend(_drift_to_finding(d) for d in drift)
    for dec in decisions:
        f = _decision_to_finding(dec)
        if f is not None:
            findings.append(f)

    scored = score_findings(findings)
    report.findings = [f.to_dict() for f in scored.findings]
    report.score = scored.score
    report.severity = scored.severity
    report.ok = scored.statistics.get("failed", 0) == 0
    dist = scored.statistics.get("severityDistribution", {})
    report.summary = (
        f"{scored.statistics.get('failed', 0)} findings "
        f"(Critical={dist.get('Critical', 0)}, High={dist.get('High', 0)}, "
        f"Medium={dist.get('Medium', 0)}, Low={dist.get('Low', 0)}); "
        f"score={scored.score}"
    )

    if build_bom:
        report.agentbom = generate_agentbom(
            audit=report,
            agent=agent,
            policy=pol,
            registry=reg,
            server=server,
        )

    return report


def audit_to_sarif(report: AuditReport | Mapping[str, Any]) -> dict[str, Any]:
    data = report.to_dict() if isinstance(report, AuditReport) else report
    return findings_to_sarif(data.get("findings") or [])


def fails_severity_threshold(report: AuditReport | Mapping[str, Any], threshold: str = "high") -> bool:
    """Return True if report severity meets or exceeds threshold (should fail CI)."""
    data = report.to_dict() if isinstance(report, AuditReport) else report
    thr = threshold.strip().capitalize()
    if thr == "High":
        thr = "High"
    elif thr.lower() == "critical":
        thr = "Critical"
    elif thr.lower() == "medium":
        thr = "Medium"
    elif thr.lower() == "low":
        thr = "Low"
    else:
        thr = thr.capitalize()
    return SEVERITY_RANK.get(str(data.get("severity") or "Low"), 0) >= SEVERITY_RANK.get(thr, 3)
