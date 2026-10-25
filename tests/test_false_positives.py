"""Benign office / update / streaming captures must not score above INFO."""
from __future__ import annotations

from pathlib import Path

from pcaplens.analyze import analyze_pcap
from pcaplens.synth import (
    build_benign_dns_pcap,
    build_clean_pcap,
    build_streaming_pcap,
    build_update_pcap,
)


def _scored(result) -> list[tuple[str, str, str]]:
    return [f for f in result.findings if f[0] != "INFO"]


def _analyse(pcap: Path, tmp_path: Path, name: str):
    return analyze_pcap(
        pcap,
        case_id=f"FP-{name}",
        examiner="pytest",
        out=tmp_path / f"out_{name}",
        tshark_cross_check=False,
    )


def test_clean_browsing_has_no_scored_findings(tmp_path: Path):
    result = _analyse(build_clean_pcap(tmp_path / "clean.pcap"), tmp_path, "browse")
    assert _scored(result) == []
    assert result.iocs == []


def test_benign_dns_has_no_scored_findings(tmp_path: Path):
    result = _analyse(build_benign_dns_pcap(tmp_path / "dns.pcap"), tmp_path, "dns")
    assert _scored(result) == []


def test_software_update_cdn_is_not_dga(tmp_path: Path):
    result = _analyse(build_update_pcap(tmp_path / "upd.pcap"), tmp_path, "upd")
    assert _scored(result) == []
    titles = {t for _s, t, _d in result.findings}
    assert not any("DGA" in t or "tunnelling" in t.lower() for t in titles)


def test_streaming_many_https_hosts_is_not_a_scan(tmp_path: Path):
    result = _analyse(build_streaming_pcap(tmp_path / "stream.pcap"), tmp_path, "stream")
    assert _scored(result) == []
    titles = {t for _s, t, _d in result.findings}
    assert not any("scan" in t.lower() for t in titles)
