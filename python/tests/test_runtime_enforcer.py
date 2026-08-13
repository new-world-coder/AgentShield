"""Tests for runtime enforcer and trace replay."""

import json
from pathlib import Path

from agentshield.runtime.config import RuntimeMode
from agentshield.runtime.enforcer import EnforcementDecision, RuntimeEnforcer
from agentshield.runtime.middleware import AgentShieldRuntime
from agentshield.runtime.policy_dsl import load_runtime_policy


EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def test_untrusted_blocks_write_file():
    policy = load_runtime_policy(EXAMPLES / "runtime_policy.yaml")
    enforcer = RuntimeEnforcer(policy=policy)
    enforcer.ingest_content("malicious ticket body", integrity="untrusted", source="rag")
    result = enforcer.check_tool_call({"name": "write_file", "arguments": {}})
    assert result.decision is EnforcementDecision.DENY
    assert result.rule_id.startswith("ifc")


def test_allowed_tool_passes():
    policy = load_runtime_policy(EXAMPLES / "runtime_policy.yaml")
    enforcer = RuntimeEnforcer(policy=policy)
    enforcer.ingest_content("benign", integrity="trusted", source="user")
    result = enforcer.check_tool_call({"name": "search_docs"})
    assert result.decision is EnforcementDecision.ALLOW


def test_development_mode_warns_instead_of_deny():
    policy = load_runtime_policy(EXAMPLES / "runtime_policy.yaml")
    policy.mode = RuntimeMode.DEVELOPMENT
    enforcer = RuntimeEnforcer(policy=policy)
    enforcer.ingest_content("x", integrity="untrusted", source="rag")
    result = enforcer.check_tool_call({"name": "write_file"})
    assert result.decision is EnforcementDecision.WARN


def test_trace_replay_blocks_second_tool():
    trace = json.loads((EXAMPLES / "runtime_trace.json").read_text(encoding="utf-8"))
    runtime = AgentShieldRuntime(policy=EXAMPLES / "runtime_policy.yaml")
    results = runtime.replay_trace(trace)
    assert results[0]["decision"] == "allow"
    assert results[1]["decision"] == "deny"


def test_policy_ast_compile():
    from agentshield.runtime.policy_dsl import compile_policy_ast

    policy = load_runtime_policy(EXAMPLES / "runtime_policy.yaml")
    ast = compile_policy_ast(policy)
    assert ast["version"] == "1.0"
    assert len(ast["rules"]) >= 1
