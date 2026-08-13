"""Tests for quarantine store."""

from agentshield.runtime.labels import FlowLabels, Integrity
from agentshield.runtime.quarantine import QuarantineStore


def test_untrusted_content_quarantined():
    store = QuarantineStore()
    labels = FlowLabels(integrity=Integrity.UNTRUSTED)
    visible, _, ref = store.ingest_if_untrusted("secret payload", labels, source="mcp")
    assert ref is not None
    assert "secret payload" not in visible
    assert store.resolve(ref.ref_id) == "secret payload"


def test_trusted_pass_through():
    store = QuarantineStore()
    labels = FlowLabels(integrity=Integrity.TRUSTED)
    visible, out_labels, ref = store.ingest_if_untrusted("hello", labels)
    assert ref is None
    assert visible == "hello"
    assert out_labels.integrity is Integrity.TRUSTED
