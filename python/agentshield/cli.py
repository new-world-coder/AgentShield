"""AgentShield CLI — MCP pin/scan and Assure utilities."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from agentshield import __version__
from agentshield.assure.oracles import evaluate_trace
from agentshield.assure.packs import expand_packs, load_pack_file
from agentshield.assure.sarif import findings_to_sarif
from agentshield.assure.scoring import Finding, findings_from_oracles, score_findings
from agentshield.mcp.firewall import ToolAllowlist
from agentshield.mcp.pin import pin_tool, verify_pin
from agentshield.mcp.scan import scan_tools


def _read_json(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _write_json(path: str | None, data: Any) -> None:
    text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    if path:
        Path(path).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)


def cmd_mcp_pin(args: argparse.Namespace) -> int:
    tool = _read_json(args.tool)
    pin = pin_tool(tool, algorithm=args.algorithm)
    if args.verify_against:
        stored = _read_json(args.verify_against)
        ok, reason = verify_pin(tool, stored)
        _write_json(args.out, {"ok": ok, "reason": reason, "pin": pin.to_dict()})
        return 0 if ok else 2
    _write_json(args.out, pin.to_dict())
    return 0


def cmd_mcp_scan(args: argparse.Namespace) -> int:
    payload = _read_json(args.tools)
    tools = payload if isinstance(payload, list) else payload.get("tools") or []
    trusted = None
    if args.trusted:
        trusted = [n.strip() for n in args.trusted.split(",") if n.strip()]
    report = scan_tools(tools, trusted_names=trusted)
    _write_json(args.out, report.to_dict())
    return 0 if report.ok else 2


def cmd_mcp_firewall(args: argparse.Namespace) -> int:
    allowed = [n.strip() for n in (args.allow or "").split(",") if n.strip()]
    approval = [n.strip() for n in (args.approve or "").split(",") if n.strip()]
    gate = ToolAllowlist(allowed, approval, fail_closed=not args.fail_open)
    result = gate.decide(args.tool_name)
    _write_json(args.out, result.to_dict())
    return 0 if result.decision.value == "allow" else 2


def cmd_packs_expand(args: argparse.Namespace) -> int:
    if args.base:
        pack = load_pack_file(args.base)
    else:
        pack = expand_packs()
    _write_json(args.out, pack)
    return 0


def cmd_oracle_evaluate(args: argparse.Namespace) -> int:
    trace = _read_json(args.trace)
    forbidden = [n.strip() for n in (args.forbidden or "").split(",") if n.strip()]
    allowed = (
        [n.strip() for n in args.allowed.split(",") if n.strip()]
        if args.allowed is not None
        else None
    )
    results = evaluate_trace(
        trace,
        forbidden_tools=forbidden,
        allowed_tools=allowed,
    )
    findings = findings_from_oracles([r.to_dict() for r in results])
    scored = score_findings(findings)
    payload = {
        "oracles": [r.to_dict() for r in results],
        "score": scored.to_dict(),
    }
    _write_json(args.out, payload)
    return 0 if all(r.passed for r in results) else 2


def cmd_sarif_export(args: argparse.Namespace) -> int:
    raw = _read_json(args.findings)
    if isinstance(raw, dict) and "oracles" in raw:
        items = raw["oracles"]
    elif isinstance(raw, dict) and "findings" in raw:
        items = raw["findings"]
    elif isinstance(raw, list):
        items = raw
    else:
        items = [raw]
    sarif = findings_to_sarif(items)
    _write_json(args.out, sarif)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentshield",
        description="AgentShield Python SDK CLI (MCP firewall + Assure)",
    )
    parser.add_argument("--version", action="version", version=f"agentshield {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    mcp = sub.add_parser("mcp", help="MCP firewall primitives")
    mcp_sub = mcp.add_subparsers(dest="mcp_command", required=True)

    pin = mcp_sub.add_parser("pin", help="Pin or verify a tool schema hash")
    pin.add_argument("--tool", required=True, help="Path to tool JSON")
    pin.add_argument("--algorithm", default="sha256")
    pin.add_argument("--verify-against", help="Existing pin JSON to verify")
    pin.add_argument("--out", help="Output path (default stdout)")
    pin.set_defaults(func=cmd_mcp_pin)

    scan = mcp_sub.add_parser("scan", help="Scan tools for poisoning / typosquat")
    scan.add_argument("--tools", required=True, help="Path to tools JSON (list or {tools:[]})")
    scan.add_argument("--trusted", help="Comma-separated trusted tool names")
    scan.add_argument("--out", help="Output path (default stdout)")
    scan.set_defaults(func=cmd_mcp_scan)

    fw = mcp_sub.add_parser("firewall", help="Evaluate allowlist decision")
    fw.add_argument("--tool-name", required=True)
    fw.add_argument("--allow", default="", help="Comma-separated allowlist")
    fw.add_argument("--approve", default="", help="Comma-separated approval-required tools")
    fw.add_argument("--fail-open", action="store_true")
    fw.add_argument("--out", help="Output path (default stdout)")
    fw.set_defaults(func=cmd_mcp_firewall)

    packs = sub.add_parser("packs", help="Mutational payload packs")
    packs_sub = packs.add_subparsers(dest="packs_command", required=True)
    expand = packs_sub.add_parser("expand", help="Expand base packs with mutations")
    expand.add_argument("--base", help="Optional base pack JSON path")
    expand.add_argument("--out", help="Output path (default stdout)")
    expand.set_defaults(func=cmd_packs_expand)

    oracle = sub.add_parser("oracle", help="Action oracles")
    oracle_sub = oracle.add_subparsers(dest="oracle_command", required=True)
    evaluate = oracle_sub.add_parser("evaluate", help="Evaluate an execution trace")
    evaluate.add_argument("--trace", required=True)
    evaluate.add_argument("--forbidden", default="", help="Comma-separated forbidden tools")
    evaluate.add_argument(
        "--allowed",
        default=None,
        help="Comma-separated allowlist (omit to skip allowlist oracle)",
    )
    evaluate.add_argument("--out", help="Output path (default stdout)")
    evaluate.set_defaults(func=cmd_oracle_evaluate)

    sarif = sub.add_parser("sarif", help="SARIF export")
    sarif_sub = sarif.add_subparsers(dest="sarif_command", required=True)
    export = sarif_sub.add_parser("export", help="Export findings to SARIF 2.1.0")
    export.add_argument("--findings", required=True)
    export.add_argument("--out", help="Output path (default stdout)")
    export.set_defaults(func=cmd_sarif_export)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
