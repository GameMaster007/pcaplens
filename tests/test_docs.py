"""Docs required for the viva walkthrough stay present and complete."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_readme_has_usage_walkthrough():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "## Usage walkthrough" in text
    assert "pcaplens analyse" in text
    assert "pcaplens report" in text
    assert "docs/viva.md" in text
    assert "docs/limitations.md" in text
    assert "gen-sample" in text
    assert "verify-custody" in text
    assert "pip install -e ." in text
    assert "samples/fixtures/syn_scan.pcap" in text
    assert "samples/fixtures/clean_browse.pcap" in text


def test_viva_doc_covers_exam_topics():
    text = (ROOT / "docs" / "viva.md").read_text(encoding="utf-8")
    for needle in (
        "median",
        "RFC 5737",
        "SNI",
        "captured",
        "LINKTYPE_LINUX_SLL",
        "yaml.safe_load",
        "Computer Misuse Act",
        "ATT&CK",
        "250",
        "exit codes",
        "1M",
        "limitations.md",
        "false-positive",
        "HTTP/2",
    ):
        assert needle in text, f"missing viva topic: {needle}"


def test_limitations_doc_is_honest():
    text = (ROOT / "docs" / "limitations.md").read_text(encoding="utf-8")
    for needle in (
        "does not",
        "false positive",
        "false negative",
        "JA3",
        "QUIC",
        "DoH",
        "VLAN",
        "Encrypted Client Hello",
        "software updater",
        "slow",
        "clean report",
    ):
        assert needle.lower() in text.lower(), f"missing limitations topic: {needle}"


def test_changelog_has_v0_2_0_draft():
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "## [0.2.0] - Draft" in text
    assert "docs/limitations.md" in text
    assert "Do not tag" in text
