"""CLI smoke tests."""
from __future__ import annotations

from pathlib import Path

from pcaplens.cli import main
from pcaplens.synth import build_clean_pcap


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


def test_cli_verify_custody(tmp_path: Path):
    pcap = build_clean_pcap(tmp_path / "c.pcap")
    out = tmp_path / "o"
    main(["analyse", str(pcap), "--out", str(out), "--no-tshark"])
    assert main(["verify-custody", str(out / "chain_of_custody.jsonl")]) == 0
