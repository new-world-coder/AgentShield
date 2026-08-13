"""Tests for hash-chained audit log."""

from pathlib import Path

from agentshield.runtime.audit_chain import AuditChain


def test_chain_verify_ok(tmp_path: Path):
    log_path = tmp_path / "audit.jsonl"
    chain = AuditChain(path=log_path)
    chain.append("tool_check", {"tool": "read_file", "decision": "allow"})
    chain.append("tool_check", {"tool": "write_file", "decision": "deny"})
    ok, reason = chain.verify()
    assert ok, reason

    reloaded = AuditChain.load(log_path)
    ok2, reason2 = reloaded.verify()
    assert ok2, reason2
    assert len(list(reloaded.entries())) == 2


def test_tamper_detected(tmp_path: Path):
    chain = AuditChain()
    chain.append("event", {"a": 1})
    entry = list(chain.entries())[0]
    chain._entries[0] = entry.__class__(
        seq=entry.seq,
        timestamp=entry.timestamp,
        event_type=entry.event_type,
        detail={"a": 999},
        prev_hash=entry.prev_hash,
        entry_hash=entry.entry_hash,
    )
    ok, reason = chain.verify()
    assert not ok
    assert "entry_hash" in reason
