"""Tests for action oracles."""

from agentshield.assure.oracles import evaluate_trace


def test_forbidden_tool_and_secret_egress():
    trace = {
        "tool_calls": [
            {"name": "shell", "result": "ok"},
            {"name": "get_time", "result": "12:00"},
        ],
        "egress": "Here is the key sk-abcdefghijklmnopqrstuvwxyz123456",
    }
    results = evaluate_trace(
        trace,
        forbidden_tools=["shell", "rm"],
        allowed_tools=["get_time"],
    )
    by_id = {r.oracle_id: r for r in results}
    assert by_id["forbidden_tool_fire"].passed is False
    assert by_id["secret_egress"].passed is False
    assert by_id["allowlist_violation"].passed is False


def test_clean_trace_passes():
    trace = {
        "tool_calls": [{"name": "get_time", "result": "12:00"}],
        "egress": "The time is noon UTC.",
        "pin_verification": {"ok": True},
    }
    results = evaluate_trace(
        trace,
        forbidden_tools=["shell"],
        allowed_tools=["get_time"],
    )
    assert all(r.passed for r in results)


def test_schema_pin_drift():
    trace = {"pin_verification": {"ok": False, "reason": "digest_mismatch"}}
    results = evaluate_trace(trace)
    drift = next(r for r in results if r.oracle_id == "schema_pin_drift")
    assert drift.passed is False
    assert drift.severity == "Critical"
