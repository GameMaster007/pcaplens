"""DNS module: NXDOMAIN bursts, DGA heuristic, odd names, tunnelling signs."""
from __future__ import annotations

from pathlib import Path

from pcaplens.analyze import analyze_pcap
from pcaplens.synth import build_clean_pcap, build_dns_abuse_pcap


def _titles(result) -> set[str]:
    return {t for _, t, _ in result.findings}


def test_dns_abuse_detections(tmp_path: Path):
    pcap = build_dns_abuse_pcap(tmp_path / "dns.pcap")
    result = analyze_pcap(
        pcap,
        case_id="DNS-1",
        examiner="pytest",
        out=tmp_path / "out",
        tshark_cross_check=False,
    )
    titles = _titles(result)
    assert any("NXDOMAIN" in t for t in titles)
    assert any("DGA" in t for t in titles)
    assert any("Odd" in t or "long DNS" in t for t in titles)
    assert any("tunnelling signs" in t.lower() or "tunnel" in t.lower() for t in titles)
    kinds = {k for k, _v, _c in result.iocs}
    assert "ip" in kinds or "domain" in kinds


def test_clean_pcap_still_has_no_dns_findings(tmp_path: Path):
    pcap = build_clean_pcap(tmp_path / "clean.pcap")
    result = analyze_pcap(
        pcap,
        case_id="DNS-CLEAN",
        examiner="pytest",
        out=tmp_path / "out_clean",
        tshark_cross_check=False,
    )
    assert result.findings == []
    assert result.iocs == []
