"""MCP tool scanning — description poisoning, typosquat, shadow tools.

Heuristics are deterministic and local (no network, no LLM judge).
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from difflib import SequenceMatcher
from typing import Any, Iterable, Mapping, Sequence


POISON_PATTERNS: list[tuple[str, re.Pattern[str], str, str]] = [
    (
        "instruction_override",
        re.compile(
            r"(ignore|disregard|override).{0,40}(previous|prior|system).{0,20}(instruction|prompt|rule)",
            re.I,
        ),
        "Critical",
        "MCP01",
    ),
    (
        "hidden_exfil",
        re.compile(
            r"(send|exfiltrat|upload|post).{0,40}(secret|api.?key|token|password|credential)",
            re.I,
        ),
        "Critical",
        "MCP01",
    ),
    (
        "privilege_claim",
        re.compile(
            r"(you (must|should) |always )?(grant|enable|use).{0,30}(admin|root|sudo|unrestricted)",
            re.I,
        ),
        "High",
        "MCP01",
    ),
    (
        "do_not_tell_user",
        re.compile(r"(do not|don't|never).{0,20}(tell|inform|reveal|mention).{0,20}(user|human)", re.I),
        "High",
        "MCP01",
    ),
    (
        "tool_priority_hijack",
        re.compile(r"(prefer|always use|must use).{0,30}(this tool|me first)", re.I),
        "Medium",
        "MCP01",
    ),
]


@dataclass
class ScanFinding:
    tool_name: str
    rule_id: str
    severity: str
    taxonomy: str
    message: str
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanReport:
    findings: list[ScanFinding] = field(default_factory=list)
    tools_scanned: int = 0

    @property
    def ok(self) -> bool:
        return not any(f.severity in ("Critical", "High") for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "tools_scanned": self.tools_scanned,
            "findings": [f.to_dict() for f in self.findings],
        }


def _lookalike_ratio(a: str, b: str) -> float:
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def _homoglyph_normalize(name: str) -> str:
    table = str.maketrans(
        {
            "0": "o",
            "1": "l",
            "3": "e",
            "4": "a",
            "5": "s",
            "7": "t",
            "@": "a",
            "$": "s",
        }
    )
    return name.lower().translate(table)


def scan_description(tool: Mapping[str, Any]) -> list[ScanFinding]:
    name = str(tool.get("name", "") or "<unnamed>")
    description = str(tool.get("description", "") or "")
    findings: list[ScanFinding] = []
    for rule_id, pattern, severity, taxonomy in POISON_PATTERNS:
        match = pattern.search(description)
        if match:
            findings.append(
                ScanFinding(
                    tool_name=name,
                    rule_id=rule_id,
                    severity=severity,
                    taxonomy=taxonomy,
                    message=f"Description poisoning heuristic matched: {rule_id}",
                    evidence=match.group(0)[:120],
                )
            )
    return findings


def scan_shadow_and_typosquat(
    tools: Sequence[Mapping[str, Any]],
    *,
    trusted_names: Iterable[str] | None = None,
    similarity_threshold: float = 0.82,
) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    names = [str(t.get("name", "")).strip() for t in tools if t.get("name")]
    trusted = {n.lower() for n in (trusted_names or [])}

    # Exact duplicate / shadow names
    seen: dict[str, int] = {}
    for n in names:
        key = n.lower()
        seen[key] = seen.get(key, 0) + 1
    for key, count in seen.items():
        if count > 1:
            findings.append(
                ScanFinding(
                    tool_name=key,
                    rule_id="shadow_tool_duplicate",
                    severity="High",
                    taxonomy="MCP03",
                    message=f"Shadow tool: name appears {count} times",
                    evidence=key,
                )
            )

    # Pairwise lookalikes
    for i, a in enumerate(names):
        for b in names[i + 1 :]:
            if a.lower() == b.lower():
                continue
            ratio = _lookalike_ratio(a, b)
            norm_ratio = _lookalike_ratio(_homoglyph_normalize(a), _homoglyph_normalize(b))
            score = max(ratio, norm_ratio)
            if score >= similarity_threshold:
                findings.append(
                    ScanFinding(
                        tool_name=a,
                        rule_id="typosquat_lookalike",
                        severity="High",
                        taxonomy="MCP08",
                        message=f"Typosquat / lookalike pair: {a!r} ~ {b!r} ({score:.2f})",
                        evidence=f"{a}|{b}|{score:.2f}",
                    )
                )

    # Untrusted names when an allowlist of trusted names is provided
    if trusted:
        for n in names:
            if n.lower() not in trusted:
                # only flag if lookalike to a trusted name
                for t in trusted:
                    if _lookalike_ratio(n, t) >= similarity_threshold and n.lower() != t:
                        findings.append(
                            ScanFinding(
                                tool_name=n,
                                rule_id="untrusted_lookalike",
                                severity="High",
                                taxonomy="MCP08",
                                message=f"Untrusted tool looks like trusted {t!r}",
                                evidence=n,
                            )
                        )
                        break

    return findings


def scan_tools(
    tools: Sequence[Mapping[str, Any]],
    *,
    trusted_names: Iterable[str] | None = None,
    similarity_threshold: float = 0.82,
) -> ScanReport:
    """Scan a set of MCP / function tools for poisoning and identity issues."""
    findings: list[ScanFinding] = []
    for tool in tools:
        findings.extend(scan_description(tool))
    findings.extend(
        scan_shadow_and_typosquat(
            tools,
            trusted_names=trusted_names,
            similarity_threshold=similarity_threshold,
        )
    )
    return ScanReport(findings=findings, tools_scanned=len(tools))
