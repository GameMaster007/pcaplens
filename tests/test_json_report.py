"""JSON report schema and edge-case tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from scapy.all import wrpcap

from pcaplens.analyze import JSON_SCHEMA_VERSION, analyze_pcap, build_json_report
from pcaplens.synth import build_clean_pcap


def _sample_report() -> dict:
    return build_json_report(
        case_id="CASE-1",
        findings=[("HIGH", "Port scan", "10.0.0.1 probed 10.0.0.2")],
        iocs=[("ip", "10.0.0.1", "scanner")],
        custody_ok=True,
        custody_summary="chain intact (4 entries)",
        custody_entries=4,
        pcap_unchanged=True,
        sha256="a" * 64,
    )


def _preserved_out(tmp_path: Path) -> tuple[Path, Path]:
    """Existing --out dir plus a marker file that must survive a failed run."""
    out = tmp_path / "keep_me"
    out.mkdir()
    marker = out / "marker.txt"
    marker.write_text("stay", encoding="utf-8")
    return out, marker


def test_json_report_round_trip_empty_findings_and_iocs():
    """Clean-case JSON still has the required keys, just empty lists."""
    payload = build_json_report(
        case_id="CLEAN",
        findings=[],
        iocs=[],
        custody_ok=True,
        custody_summary="chain intact (1 entry)",
        custody_entries=1,
        pcap_unchanged=True,
        sha256="b" * 64,
    )
    data = json.loads(json.dumps(payload, ensure_ascii=False))
    assert data["schema_version"] == JSON_SCHEMA_VERSION
    assert data["findings"] == []
    assert data["iocs"] == []
    assert data["custody"]["entries"] == 1


def test_json_report_round_trip_unicode():
    """Non-ASCII case IDs, titles, and IOC values must survive json.loads."""
    payload = build_json_report(
        case_id="案件-café-🔍",
        findings=[("HIGH", "隧道 DNS", "query café.example")],
        iocs=[("domain", "café.example", "unicode hostname")],
        custody_ok=True,
        custody_summary="chain intact (2 entries)",
        custody_entries=2,
        pcap_unchanged=True,
        sha256="c" * 64,
    )
    raw = json.dumps(payload, ensure_ascii=False)
    data = json.loads(raw)
    assert data["case_id"] == "案件-café-🔍"
    assert data["findings"][0]["title"] == "隧道 DNS"
    assert data["iocs"][0]["value"] == "café.example"


def test_json_report_round_trip_very_large_values():
    """Long strings and large integers stay JSON-safe."""
    huge = "X" * 200_000
    payload = build_json_report(
        case_id="BIG",
        findings=[("LOW", "Noise", huge)],
        iocs=[("url", "http://example/" + huge[:100], huge)],
        custody_ok=False,
        custody_summary="chain broken at entry 1: prev_hash mismatch",
        custody_entries=10**12,
        pcap_unchanged=False,
        sha256="d" * 64,
    )
    data = json.loads(json.dumps(payload, ensure_ascii=False))
    assert len(data["findings"][0]["detail"]) == 200_000
    assert data["custody"]["entries"] == 10**12
    assert data["custody"]["intact"] is False


def test_unknown_format_does_not_wipe_out(tmp_path: Path):
    """A bad report_format must fail before analyze_pcap deletes --out."""
    out, marker = _preserved_out(tmp_path)
    with pytest.raises(ValueError, match="unsupported report format"):
        analyze_pcap(tmp_path / "missing.pcap", out=out, report_format="yaml")
    assert marker.read_text(encoding="utf-8") == "stay"


def test_missing_pcap_does_not_wipe_out(tmp_path: Path):
    """A missing capture must fail before analyze_pcap deletes --out."""
    out, marker = _preserved_out(tmp_path)
    with pytest.raises(FileNotFoundError, match="PCAP not found"):
        analyze_pcap(tmp_path / "missing.pcap", out=out, report_format="json")
    assert marker.read_text(encoding="utf-8") == "stay"


def test_empty_capture_raises_before_writing_report(tmp_path: Path):
    pcap = tmp_path / "empty.pcap"
    wrpcap(str(pcap), [])
    out = tmp_path / "out"
    with pytest.raises(ValueError, match="no packets"):
        analyze_pcap(pcap, out=out, report_format="json", tshark_cross_check=False)
    assert not (out / "report.json").exists()
    assert not (out / "report.md").exists()


def test_clean_pcap_json_has_no_findings(tmp_path: Path):
    pcap = build_clean_pcap(tmp_path / "clean.pcap")
    result = analyze_pcap(
        pcap,
        case_id="CLEAN-JSON",
        out=tmp_path / "out",
        tshark_cross_check=False,
        report_format="json",
    )
    data = json.loads(result.report_path.read_text(encoding="utf-8"))
    assert data["findings"] == []
    assert data["case_id"] == "CLEAN-JSON"
    assert (tmp_path / "out" / "iocs.csv").is_file()
    assert (tmp_path / "out" / "chain_of_custody.jsonl").is_file()


def test_sample_report_has_stable_keys():
    data = _sample_report()
    assert set(data) == {"schema_version", "case_id", "findings", "iocs", "custody"}
    assert set(data["findings"][0]) == {"severity", "title", "detail"}
    assert set(data["iocs"][0]) == {"type", "value", "context"}
    assert set(data["custody"]) == {
        "summary",
        "intact",
        "entries",
        "pcap_unchanged",
        "sha256",
    }
