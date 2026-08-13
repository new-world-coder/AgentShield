"""Tests for IFC label merge rules."""

from agentshield.runtime.labels import Confidentiality, FlowLabels, Integrity


def test_merge_integrity_most_restrictive():
    a = FlowLabels(integrity=Integrity.TRUSTED)
    b = FlowLabels(integrity=Integrity.UNTRUSTED)
    merged = a.merge(b)
    assert merged.integrity is Integrity.UNTRUSTED


def test_merge_confidentiality_most_restrictive():
    a = FlowLabels(confidentiality=Confidentiality.PUBLIC)
    b = FlowLabels(confidentiality=Confidentiality.PRIVATE)
    merged = a.merge(b)
    assert merged.confidentiality is Confidentiality.PRIVATE


def test_roundtrip_dict():
    labels = FlowLabels(integrity=Integrity.UNTRUSTED, confidentiality=Confidentiality.PRIVATE)
    restored = FlowLabels.from_dict(labels.to_dict())
    assert restored == labels
