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
    assert "gen-sample" in text
    assert "verify-custody" in text


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
    ):
        assert needle in text, f"missing viva topic: {needle}"
