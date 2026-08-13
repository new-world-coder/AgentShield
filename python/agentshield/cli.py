"""AgentShield CLI — MCP firewall, audit, registry, BOM, Assure utilities."""

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
from agentshield.assure.scoring import findings_from_oracles, score_findings
from agentshield.bom.agentbom import generate_agentbom, load_audit_report
from agentshield.mcp.adapter import ServerConfig
from agentshield.mcp.audit import (
    audit_to_sarif,
    fails_severity_threshold,
    run_mcp_security_audit,
)
from agentshield.mcp.firewall import ToolAllowlist
from agentshield.mcp.pin import pin_tool, verify_pin
from agentshield.mcp.policy import load_policy
from agentshield.mcp.registry import PinRegistry
from agentshield.runtime.audit_chain import AuditChain
from agentshield.runtime.enforcer import RuntimeEnforcer
from agentshield.runtime.policy_dsl import compile_policy_ast, load_runtime_policy


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


def cmd_mcp_audit(args: argparse.Namespace) -> int:
    config: Any
    if args.server:
        config = _read_json(args.server)
    elif args.tools:
        config = ServerConfig(id=args.server_id or "file", transport="file", path=args.tools)
    else:
        sys.stderr.write("mcp audit requires --tools or --server\n")
        return 2

    report = run_mcp_security_audit(
        config,
        policy=args.policy,
        pins_path=args.pins,
        verify_pins=not args.skip_pin_verify,
        include_unpinned=not args.ignore_unpinned,
        agent={"name": args.agent_name or "", "adapter": args.adapter or "", "model": args.model or ""},
    )
    payload = report.to_dict()
    if args.sarif:
        sarif = audit_to_sarif(report)
        Path(args.sarif).write_text(json.dumps(sarif, indent=2) + "\n", encoding="utf-8")
        payload["sarif_path"] = args.sarif
    _write_json(args.out, payload)

    if args.fail_on_severity:
        if fails_severity_threshold(report, args.fail_on_severity):
            return 2
        return 0
    return 0 if report.ok else 2


def cmd_pin_registry_add(args: argparse.Namespace) -> int:
    payload = _read_json(args.tools)
    tools = payload if isinstance(payload, list) else payload.get("tools") or [payload]
    reg = PinRegistry(args.pins)
    records = reg.pin_all(tools, server_id=args.server_id)
    _write_json(args.out, {"pins": [r.to_dict() for r in records], "path": str(reg.path)})
    return 0


def cmd_pin_registry_verify(args: argparse.Namespace) -> int:
    payload = _read_json(args.tools)
    tools = payload if isinstance(payload, list) else payload.get("tools") or [payload]
    reg = PinRegistry(args.pins)
    findings = reg.verify_tools(tools, server_id=args.server_id)
    _write_json(
        args.out,
        {
            "ok": len(findings) == 0,
            "findings": [f.to_dict() for f in findings],
            "path": str(reg.path),
        },
    )
    return 0 if not findings else 2


def cmd_pin_registry_list(args: argparse.Namespace) -> int:
    reg = PinRegistry(args.pins)
    pins = reg.list_pins(args.server_id)
    _write_json(args.out, {"pins": [p.to_dict() for p in pins], "path": str(reg.path)})
    return 0


def cmd_bom_generate(args: argparse.Namespace) -> int:
    report = load_audit_report(args.audit_report)
    bom = generate_agentbom(
        audit_report=report,
        agent={
            "name": args.agent_name or report.get("server_id") or "agent",
            "adapter": args.adapter or "file",
            "model": args.model or "",
        },
        policy=load_policy(args.policy) if args.policy else None,
    )
    _write_json(args.out, bom)
    return 0


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


def cmd_runtime_check(args: argparse.Namespace) -> int:
    trace = _read_json(args.trace)
    policy = load_runtime_policy(args.policy) if args.policy else load_runtime_policy(None)
    audit = None
    if args.audit_log:
        audit = AuditChain.load(args.audit_log)
        audit.path = Path(args.audit_log)
    enforcer = RuntimeEnforcer(policy=policy, audit=audit)
    results = enforcer.evaluate_trace(trace)
    audit_status = None
    if args.audit_log and audit:
        ok, reason = audit.verify()
        audit_status = {"ok": ok, "reason": reason}
    payload = {
        "ok": all(r.decision.value in ("allow", "warn") for r in results),
        "results": [r.to_dict() for r in results],
        "labels_in_scope": enforcer.context.labels_in_scope.to_dict(),
    }
    if audit_status:
        payload["audit_chain"] = audit_status
    _write_json(args.out, payload)
    if any(r.decision.value in ("deny", "require_approval") for r in results):
        return 2
    return 0


def cmd_runtime_audit_verify(args: argparse.Namespace) -> int:
    chain = AuditChain.load(args.log)
    ok, reason = chain.verify()
    _write_json(args.out, {"ok": ok, "reason": reason, "entries": len(list(chain.entries()))})
    return 0 if ok else 2


def cmd_runtime_policy_ast(args: argparse.Namespace) -> int:
    policy = load_runtime_policy(args.policy)
    ast = compile_policy_ast(policy)
    _write_json(args.out, ast)
    return 0
    parser = argparse.ArgumentParser(
        prog="agentshield",
        description="AgentShield Python SDK CLI (MCP firewall + Assure)",
    )
    parser.add_argument("--version", action="version", version=f"agentshield {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    mcp = sub.add_parser("mcp", help="MCP firewall / audit")
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

    audit = mcp_sub.add_parser("audit", help="Run full MCP security audit pipeline")
    audit.add_argument("--tools", help="Path to tools JSON file")
    audit.add_argument("--server", help="Path to MCP server config JSON")
    audit.add_argument("--server-id", default="default")
    audit.add_argument("--policy", help="Path to policy YAML/JSON")
    audit.add_argument("--pins", help="Path to pin registry JSON")
    audit.add_argument("--skip-pin-verify", action="store_true")
    audit.add_argument("--ignore-unpinned", action="store_true")
    audit.add_argument("--fail-on-severity", help="Fail if severity >= threshold (e.g. high)")
    audit.add_argument("--sarif", help="Write SARIF output to path")
    audit.add_argument("--agent-name", default="")
    audit.add_argument("--adapter", default="")
    audit.add_argument("--model", default="")
    audit.add_argument("--out", help="Output path (default stdout)")
    audit.set_defaults(func=cmd_mcp_audit)

    preg = mcp_sub.add_parser("pin-registry", help="Persistent pin registry")
    preg_sub = preg.add_subparsers(dest="pin_registry_command", required=True)

    preg_add = preg_sub.add_parser("add", help="Pin all tools into registry")
    preg_add.add_argument("--tools", required=True)
    preg_add.add_argument("--server-id", default="default")
    preg_add.add_argument("--pins", help="Registry path")
    preg_add.add_argument("--out")
    preg_add.set_defaults(func=cmd_pin_registry_add)

    preg_verify = preg_sub.add_parser("verify", help="Verify live tools against registry")
    preg_verify.add_argument("--tools", required=True)
    preg_verify.add_argument("--server-id", default="default")
    preg_verify.add_argument("--pins", help="Registry path")
    preg_verify.add_argument("--out")
    preg_verify.set_defaults(func=cmd_pin_registry_verify)

    preg_list = preg_sub.add_parser("list", help="List stored pins")
    preg_list.add_argument("--server-id", default=None)
    preg_list.add_argument("--pins", help="Registry path")
    preg_list.add_argument("--out")
    preg_list.set_defaults(func=cmd_pin_registry_list)

    bom = sub.add_parser("bom", help="AgentBOM generation")
    bom_sub = bom.add_subparsers(dest="bom_command", required=True)
    bom_gen = bom_sub.add_parser("generate", help="Generate AgentBOM from audit report")
    bom_gen.add_argument("--audit-report", required=True)
    bom_gen.add_argument("--policy", help="Optional policy file for hash")
    bom_gen.add_argument("--agent-name", default="")
    bom_gen.add_argument("--adapter", default="")
    bom_gen.add_argument("--model", default="")
    bom_gen.add_argument("--out")
    bom_gen.set_defaults(func=cmd_bom_generate)

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

    runtime = sub.add_parser("runtime", help="Runtime SDK — IFC enforcement + audit chain")
    runtime_sub = runtime.add_subparsers(dest="runtime_command", required=True)

    rt_check = runtime_sub.add_parser("check", help="Replay trace against runtime policy")
    rt_check.add_argument("--trace", required=True, help="Execution trace JSON")
    rt_check.add_argument("--policy", help="Runtime policy YAML/JSON")
    rt_check.add_argument("--audit-log", help="Append decisions to hash-chained JSONL log")
    rt_check.add_argument("--out", help="Output path (default stdout)")
    rt_check.set_defaults(func=cmd_runtime_check)

    rt_verify = runtime_sub.add_parser("audit-verify", help="Verify tamper-evident audit log")
    rt_verify.add_argument("--log", required=True, help="Audit JSONL path")
    rt_verify.add_argument("--out", help="Output path (default stdout)")
    rt_verify.set_defaults(func=cmd_runtime_audit_verify)

    rt_ast = runtime_sub.add_parser("policy-ast", help="Compile runtime policy to AST")
    rt_ast.add_argument("--policy", required=True)
    rt_ast.add_argument("--out", help="Output path (default stdout)")
    rt_ast.set_defaults(func=cmd_runtime_policy_ast)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
