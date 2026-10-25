"""End-to-end contract: committed fixtures, JSON schema, exit codes."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pcaplens.cli import main
from pcaplens.json_schema import JsonSchemaError, validate_json_report

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "samples" / "fixtures"


def test_fixture_pcaps_are_committed_and_small():
    for name in ("clean_browse.pcap", "syn_scan.pcap", "truncated.pcap"):
        path = FIXTURES / name
        assert path.is_file(), f"run scripts/generate_fixtures.py to create {name}"
        assert path.stat().st_size < 16_384


def test_e2e_clean_fixture_json_schema(tmp_path: Path):
    out = tmp_path / "clean"
    rc = main(
        [
            "analyse",
            str(FIXTURES / "clean_browse.pcap"),
            "--format",
            "json",
            "--case-id",
            "E2E-CLEAN",
            "--out",
            str(out),
            "--no-tshark",
        ]
    )
    assert rc == 0
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    validate_json_report(data)
    assert data["case_id"] == "E2E-CLEAN"
    assert data["findings"] == []
    assert data["iocs"] == []


def test_e2e_syn_scan_fixture_report_html(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    """README quickstart: report the committed SYN-scan fixture."""
    out = tmp_path / "output-report"
    rc = main(
        [
            "report",
            str(FIXTURES / "syn_scan.pcap"),
            "--case-id",
            "DEMO-001",
            "--out",
            str(out),
            "--no-tshark",
        ]
    )
    captured = capsys.readouterr()
    assert rc == 0
    assert (out / "report.md").is_file()
    assert (out / "report.html").is_file()
    assert "finding" in captured.out
    assert "IOC" in captured.out
    text = (out / "report.md").read_text(encoding="utf-8")
    assert "SYN scan" in text
    assert "Network Forensics Report - DEMO-001" in text


def test_e2e_syn_scan_fixture_has_finding(tmp_path: Path):
    out = tmp_path / "scan"
    rc = main(
        [
            "analyse",
            str(FIXTURES / "syn_scan.pcap"),
            "--format",
            "json",
            "--case-id",
            "E2E-SCAN",
            "--out",
            str(out),
            "--no-tshark",
        ]
    )
    assert rc == 0
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    validate_json_report(data)
    titles = {row["title"] for row in data["findings"]}
    assert any("SYN scan" in t for t in titles)


def test_e2e_truncated_fixture_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    rc = main(
        [
            "analyse",
            str(FIXTURES / "truncated.pcap"),
            "--out",
            str(tmp_path / "bad"),
            "--no-tshark",
        ]
    )
    err = capsys.readouterr().err
    assert rc == 2
    assert "error:" in err
    assert "Traceback" not in err


def test_e2e_missing_file_exits_1(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    rc = main(
        [
            "analyse",
            str(tmp_path / "nope.pcap"),
            "--out",
            str(tmp_path / "o"),
            "--no-tshark",
        ]
    )
    assert rc == 1
    assert "not found" in capsys.readouterr().err.lower()


def test_e2e_usage_exits_2():
    with pytest.raises(SystemExit) as exc:
        main(["analyse"])
    assert exc.value.code == 2


def test_json_schema_rejects_bad_objects():
    with pytest.raises(JsonSchemaError):
        validate_json_report({"schema_version": "1.0"})
    with pytest.raises(JsonSchemaError):
        validate_json_report("nope")
