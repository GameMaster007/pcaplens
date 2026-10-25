"""HTTP module: scripted UAs, suspicious URLs, hashed downloads."""
from __future__ import annotations

from pathlib import Path

from pcaplens.analyze import analyze_pcap
from pcaplens.http_analysis import parse_http, sniff_type
from pcaplens.synth import build_attack_pcap, build_clean_pcap, build_http_abuse_pcap


def _titles(result) -> set[str]:
    return {t for _, t, _ in result.findings}


def test_http_abuse_detections(tmp_path: Path):
    pcap = build_http_abuse_pcap(tmp_path / "http.pcap")
    result = analyze_pcap(
        pcap,
        case_id="HTTP-1",
        examiner="pytest",
        out=tmp_path / "out",
        tshark_cross_check=False,
    )
    titles = _titles(result)
    assert any("user-agent" in t.lower() for t in titles)
    assert any("Suspicious HTTP URL" in t for t in titles)
    assert any("file download" in t.lower() for t in titles)
    kinds = {k for k, _v, _c in result.iocs}
    assert "user-agent" in kinds
    assert "url" in kinds
    assert "sha256" in kinds
    sha_iocs = [v for k, v, _c in result.iocs if k == "sha256"]
    assert sha_iocs and all(len(v) == 64 for v in sha_iocs)


def test_http_abuse_does_not_flag_ordinary_html(tmp_path: Path):
    pcap = build_http_abuse_pcap(tmp_path / "http.pcap")
    result = analyze_pcap(
        pcap,
        case_id="HTTP-2",
        examiner="pytest",
        out=tmp_path / "out",
        tshark_cross_check=False,
    )
    details = " ".join(d for _s, _t, d in result.findings)
    assert "ordinary page" not in details
    assert "news.example" not in details


def test_clean_pcap_still_has_no_http_findings(tmp_path: Path):
    pcap = build_clean_pcap(tmp_path / "clean.pcap")
    result = analyze_pcap(
        pcap,
        case_id="HTTP-CLEAN",
        examiner="pytest",
        out=tmp_path / "out_clean",
        tshark_cross_check=False,
    )
    assert result.findings == []
    assert result.iocs == []


def test_executable_download_not_duplicated_as_http_file(tmp_path: Path):
    pcap = build_attack_pcap(tmp_path / "attack.pcap")
    result = analyze_pcap(
        pcap,
        case_id="HTTP-EXE",
        examiner="pytest",
        out=tmp_path / "out_exe",
        tshark_cross_check=False,
    )
    titles = _titles(result)
    assert any("Executable" in t for t in titles)
    exe_details = [
        d for _s, t, d in result.findings if "file download" in t.lower()
    ]
    assert not any(".exe" in d or "windows-executable" in d for d in exe_details)


def test_parse_http_and_sniff_type_helpers():
    msgs = parse_http(b"GET /x HTTP/1.1\r\nHost: a.example\r\n\r\n")
    assert msgs and msgs[0][0].startswith("GET")
    assert sniff_type(b"PK\x03\x04rest") == "zip/office"
    assert sniff_type(b"<html>ok</html>") == "html"
