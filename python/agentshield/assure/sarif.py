"""SARIF 2.1.0 export for AgentShield findings."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from agentshield.assure.scoring import Finding, score_findings
from agentshield import __version__


_LEVEL = {
    "Critical": "error",
    "High": "error",
    "Medium": "warning",
    "Low": "note",
}


def findings_to_sarif(
    findings: Sequence[Finding | Mapping[str, Any]],
    *,
    tool_name: str = "agentshield",
    tool_version: str | None = None,
) -> dict[str, Any]:
    """Convert findings / oracle results into a SARIF 2.1.0 log."""
    report = score_findings(findings)
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in report.findings:
        if finding.passed:
            continue
        rule_id = finding.rule_id
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": finding.message or rule_id},
                "fullDescription": {
                    "text": finding.evidence or finding.message or rule_id
                },
                "defaultConfiguration": {
                    "level": _LEVEL.get(finding.severity or "Medium", "warning")
                },
                "properties": {
                    "security-severity": finding.severity,
                    "impact": finding.impact,
                    "taxonomy": finding.taxonomy,
                },
            }
        results.append(
            {
                "ruleId": rule_id,
                "level": _LEVEL.get(finding.severity or "Medium", "warning"),
                "message": {"text": finding.message or finding.evidence or rule_id},
                "properties": {
                    "confidence": finding.confidence,
                    "impact": finding.impact,
                    "taxonomy": finding.taxonomy,
                    "evidence": finding.evidence,
                    "score": report.score,
                },
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version or __version__,
                        "informationUri": "https://github.com/new-world-coder/agentshield",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {
                    "agentshield.score": report.score,
                    "agentshield.severity": report.severity,
                    "agentshield.statistics": report.statistics,
                },
            }
        ],
    }
