"""Port-scan, SYN-scan, and horizontal-scan detections."""
from __future__ import annotations

from pathlib import Path

from pcaplens.analyze import analyze_pcap
from pcaplens.synth import (
    build_attack_pcap,
    build_clean_pcap,
    build_horizontal_scan_pcap,
    build_syn_scan_pcap,
)
from pcaplens.thresholds import Thresholds


def _titles(result) -> set[str]:
    return {t for _, t, _ in result.findings}


def test_syn_scan_half_open(tmp_path: Path):
    pcap = build_syn_scan_pcap(tmp_path / "syn.pcap")
    result = analyze_pcap(
        pcap,
        case_id="SCAN-SYN",
        examiner="pytest",
        out=tmp_path / "out",
        tshark_cross_check=False,
    )
    titles = _titles(result)
    assert any("SYN scan" in t for t in titles)
    # 30 ports is below SCAN_PORTS=50, so the vertical rule must stay quiet.
    assert not any(t == "Port scan" for t in titles)
    assert any(k == "ip" for k, _v, _c in result.iocs)


def test_horizontal_scan(tmp_path: Path):
    pcap = build_horizontal_scan_pcap(tmp_path / "horiz.pcap")
    result = analyze_pcap(
        pcap,
        case_id="SCAN-H",
        examiner="pytest",
        out=tmp_path / "out",
        tshark_cross_check=False,
    )
    titles = _titles(result)
    assert any("Horizontal" in t for t in titles)
    assert not any(t == "Port scan" for t in titles)
    assert not any("SYN scan" in t for t in titles)


def test_attack_pcap_still_reports_port_scan(tmp_path: Path):
    pcap = build_attack_pcap(tmp_path / "attack.pcap")
    result = analyze_pcap(
        pcap,
        case_id="SCAN-A",
        examiner="pytest",
        out=tmp_path / "out",
        tshark_cross_check=False,
    )
    titles = _titles(result)
    assert any(t == "Port scan" for t in titles)
    assert any("SYN scan" in t for t in titles)


def test_clean_pcap_has_no_scan_findings(tmp_path: Path):
    pcap = build_clean_pcap(tmp_path / "clean.pcap")
    result = analyze_pcap(
        pcap,
        case_id="SCAN-CLEAN",
        examiner="pytest",
        out=tmp_path / "out_clean",
        tshark_cross_check=False,
    )
    assert result.findings == []


def test_syn_scan_respects_completed_handshakes(tmp_path: Path):
    """Raising SCAN_PORTS must not invent a vertical scan on the SYN-scan pcap."""
    pcap = build_syn_scan_pcap(tmp_path / "syn.pcap")
    result = analyze_pcap(
        pcap,
        case_id="SCAN-THR",
        examiner="pytest",
        out=tmp_path / "out_thr",
        tshark_cross_check=False,
        thresholds=Thresholds(SCAN_PORTS=200, SCAN_WINDOW=60),
    )
    titles = _titles(result)
    assert any("SYN scan" in t for t in titles)
    assert not any(t == "Port scan" for t in titles)
