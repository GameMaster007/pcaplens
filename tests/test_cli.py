"""CLI smoke tests."""
from __future__ import annotations

import json
from pathlib import Path

from pcaplens.cli import main
from pcaplens.synth import build_attack_pcap, build_clean_pcap


def test_cli_gen_sample(tmp_path: Path):
    out = tmp_path / "s.pcap"
    assert main(["gen-sample", "--out", str(out), "--clean"]) == 0
    assert out.is_file() and out.stat().st_size > 0


def test_cli_analyse(tmp_path: Path):
    pcap = build_clean_pcap(tmp_path / "c.pcap")
    out = tmp_path / "report_dir"
    rc = main(
        [
            "analyse",
            str(pcap),
            "--case-id",
            "CLI-1",
            "--out",
            str(out),
            "--no-tshark",
        ]
    )
    assert rc == 0
    assert (out / "report.md").is_file()


def test_cli_analyse_json_round_trips(tmp_path: Path):
    """--format json writes a documented report that json.loads can parse."""
    pcap = build_attack_pcap(tmp_path / "a.pcap")
    out = tmp_path / "json_dir"
    rc = main(
        [
            "analyse",
            str(pcap),
            "--format",
            "json",
            "--case-id",
            "JSON-1",
            "--out",
            str(out),
            "--no-tshark",
        ]
    )
    assert rc == 0
    raw = (out / "report.json").read_text(encoding="utf-8")
    data = json.loads(raw)
    assert data["schema_version"] == "1.0"
    assert data["case_id"] == "JSON-1"
    assert isinstance(data["findings"], list) and data["findings"]
    assert {"severity", "title", "detail"} <= set(data["findings"][0])
    assert isinstance(data["iocs"], list) and data["iocs"]
    assert {"type", "value", "context"} <= set(data["iocs"][0])
    custody = data["custody"]
    assert custody["summary"]
    assert custody["intact"] is True
    assert custody["entries"] >= 1
    assert custody["pcap_unchanged"] is True
    assert len(custody["sha256"]) == 64
    # Markdown remains the default; JSON mode writes report.json only.
    assert not (out / "report.md").exists()


def test_cli_verify_custody(tmp_path: Path):
    pcap = build_clean_pcap(tmp_path / "c.pcap")
    out = tmp_path / "o"
    main(["analyse", str(pcap), "--out", str(out), "--no-tshark"])
    assert main(["verify-custody", str(out / "chain_of_custody.jsonl")]) == 0
