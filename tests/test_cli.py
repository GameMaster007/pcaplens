"""CLI smoke tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from scapy.all import wrpcap

from pcaplens.cli import main
from pcaplens.synth import build_attack_pcap, build_clean_pcap


def _analyse(pcap: Path, out: Path, *extra: str) -> int:
    return main(["analyse", str(pcap), *extra, "--out", str(out), "--no-tshark"])


def _assert_usage_error(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 2


def test_cli_gen_sample(tmp_path: Path):
    out = tmp_path / "s.pcap"
    assert main(["gen-sample", "--out", str(out), "--clean"]) == 0
    assert out.is_file() and out.stat().st_size > 0


def test_cli_analyse(tmp_path: Path):
    pcap = build_clean_pcap(tmp_path / "c.pcap")
    out = tmp_path / "report_dir"
    assert _analyse(pcap, out, "--case-id", "CLI-1") == 0
    assert (out / "report.md").is_file()


def test_cli_analyse_json_round_trips(tmp_path: Path):
    """--format json writes a documented report that json.loads can parse."""
    pcap = build_attack_pcap(tmp_path / "a.pcap")
    out = tmp_path / "json_dir"
    assert _analyse(pcap, out, "--format", "json", "--case-id", "JSON-1") == 0
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
    _analyse(pcap, out)
    assert main(["verify-custody", str(out / "chain_of_custody.jsonl")]) == 0


def test_cli_analyse_explicit_markdown(tmp_path: Path):
    pcap = build_clean_pcap(tmp_path / "c.pcap")
    out = tmp_path / "md"
    assert _analyse(pcap, out, "--format", "markdown") == 0
    assert (out / "report.md").is_file()
    assert not (out / "report.json").exists()


def test_cli_analyse_json_unicode_case_id(tmp_path: Path):
    pcap = build_clean_pcap(tmp_path / "c.pcap")
    out = tmp_path / "uni"
    assert _analyse(pcap, out, "--format", "json", "--case-id", "案件-café") == 0
    raw = (out / "report.json").read_text(encoding="utf-8")
    assert "案件-café" in raw
    data = json.loads(raw)
    assert data["case_id"] == "案件-café"


def test_cli_analyse_empty_pcap(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    pcap = tmp_path / "empty.pcap"
    wrpcap(str(pcap), [])
    assert _analyse(pcap, tmp_path / "o", "--format", "json") == 2
    err = capsys.readouterr().err
    assert "error:" in err
    assert "no packets" in err


def test_cli_rejects_unknown_format():
    _assert_usage_error(["analyse", "capture.pcap", "--format", "yaml"])


def test_cli_rejects_uppercase_format():
    _assert_usage_error(["analyse", "capture.pcap", "--format", "JSON"])


def test_cli_format_requires_a_value():
    _assert_usage_error(["analyse", "capture.pcap", "--format"])


def test_cli_missing_pcap(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    assert _analyse(tmp_path / "nope.pcap", tmp_path / "o", "--format", "json") == 1
    err = capsys.readouterr().err
    assert "error:" in err
    assert "PCAP not found" in err


def test_cli_help_lists_examples_and_exit_codes(capsys: pytest.CaptureFixture[str]):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    text = capsys.readouterr().out
    assert "pcaplens analyse capture.pcap" in text
    assert "exit codes:" in text
    assert "130 interrupted" in text


def test_cli_last_format_flag_wins(tmp_path: Path):
    """Repeated --format flags: argparse keeps the last value."""
    pcap = build_clean_pcap(tmp_path / "c.pcap")
    out = tmp_path / "last"
    assert _analyse(pcap, out, "--format", "json", "--format", "markdown") == 0
    assert (out / "report.md").is_file()
    assert not (out / "report.json").exists()
