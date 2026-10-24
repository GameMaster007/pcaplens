"""TLS ClientHello SNI extraction (issue #1)."""
from __future__ import annotations

from pathlib import Path

import pytest
from scapy.all import TCP, rdpcap

from pcaplens.analyze import analyze_pcap
from pcaplens.synth import TLS_SNI_HOST, build_client_hello, build_tls_sni_pcap
from pcaplens.tls import extract_sni


def _analyse(pcap: Path, tmp_path: Path, name: str):
    return analyze_pcap(
        pcap,
        case_id=f"TEST-{name.upper()}",
        examiner="pytest",
        out=tmp_path / f"out_{name}",
        tshark_cross_check=False,
    )


def _sni_findings(result) -> list[str]:
    return [detail for _, title, detail in result.findings if title == "TLS SNI"]


def _sni_iocs(result) -> list[str]:
    return [
        value
        for kind, value, context in result.iocs
        if kind == "domain" and "TLS SNI" in context
    ]


def test_extract_sni_from_bytes():
    assert extract_sni(build_client_hello(TLS_SNI_HOST)) == TLS_SNI_HOST


def test_extract_sni_missing_extension():
    assert extract_sni(build_client_hello(None)) is None


def test_extract_sni_empty_hostname():
    assert extract_sni(build_client_hello("")) is None
    assert extract_sni(build_client_hello(b"")) is None


def test_extract_sni_non_ascii_hostname():
    assert extract_sni(build_client_hello("café")) is None
    assert extract_sni(build_client_hello("café".encode())) is None
    assert extract_sni(build_client_hello(b"\xff\xfe.example")) is None


def test_extract_sni_rejects_nul_whitespace_and_oversize():
    assert extract_sni(build_client_hello(b"bad\x00host.example")) is None
    assert extract_sni(build_client_hello("spaced name.example")) is None
    assert extract_sni(build_client_hello("x" * 254)) is None


def test_extract_sni_several_entries_uses_first_valid():
    hello = build_client_hello(
        TLS_SNI_HOST,
        extra_hostnames=["backup.example"],
    )
    assert extract_sni(hello) == TLS_SNI_HOST


def test_extract_sni_skips_empty_then_reads_next():
    hello = build_client_hello(b"", extra_hostnames=[TLS_SNI_HOST])
    assert extract_sni(hello) == TLS_SNI_HOST


def test_extract_sni_skips_grease_extension():
    hello = build_client_hello(TLS_SNI_HOST, grease=True)
    assert b"\x0a\x0a" in hello and b"\x1a\x1a" in hello
    assert extract_sni(hello) == TLS_SNI_HOST
    assert extract_sni(build_client_hello(None, grease=True)) is None


def test_extract_sni_truncated_prefixes_are_safe():
    hello = build_client_hello(TLS_SNI_HOST)
    for n in range(len(hello)):
        assert extract_sni(hello[:n]) is None
    assert extract_sni(hello) == TLS_SNI_HOST


@pytest.mark.parametrize(
    "blob",
    [
        b"",
        b"\x16",
        b"\x16\x03\x03",
        b"\x16\x03\x03\xff\xff",  # length past the buffer
        b"GET / HTTP/1.1\r\n\r\n",
        b"\x16\x03\x03\x00\x04\x02\x00\x00\x00",  # ServerHello, not ClientHello
        b"\x17\x03\x03\x00\x01\x00",  # application data
        bytes(range(64)),
    ],
)
def test_extract_sni_malformed_returns_none(blob: bytes):
    assert extract_sni(blob) is None


def test_sni_in_findings_and_iocs(tmp_path: Path):
    pcap = build_tls_sni_pcap(tmp_path / "sni.pcap")
    result = _analyse(pcap, tmp_path, "sni")
    assert any(TLS_SNI_HOST in detail for detail in _sni_findings(result))
    assert TLS_SNI_HOST in _sni_iocs(result)
    assert TLS_SNI_HOST in result.report_path.read_text(encoding="utf-8")


def test_sni_from_clienthello_split_across_tcp_segments(tmp_path: Path):
    hello = build_client_hello(TLS_SNI_HOST)
    # mss well under the hello size so the capture has several TCP payloads.
    assert len(hello) > 20
    pcap = build_tls_sni_pcap(tmp_path / "split.pcap", mss=16)
    payload_pkts = [p for p in rdpcap(str(pcap)) if TCP in p and bytes(p[TCP].payload)]
    assert len(payload_pkts) >= 3
    result = _analyse(pcap, tmp_path, "split")
    assert _sni_findings(result)
    assert TLS_SNI_HOST in _sni_iocs(result)


def test_sni_on_non_443_port(tmp_path: Path):
    pcap = build_tls_sni_pcap(tmp_path / "altport.pcap", dport=8443)
    result = _analyse(pcap, tmp_path, "altport")
    assert any(":8443" in detail and TLS_SNI_HOST in detail for detail in _sni_findings(result))
    assert TLS_SNI_HOST in _sni_iocs(result)


def test_duplicate_flows_emit_one_finding_and_ioc(tmp_path: Path):
    pcap = build_tls_sni_pcap(tmp_path / "dup.pcap", sessions=2)
    result = _analyse(pcap, tmp_path, "dup")
    assert len(_sni_findings(result)) == 1
    assert _sni_iocs(result).count(TLS_SNI_HOST) == 1


def test_empty_hostname_pcap_has_no_sni_finding(tmp_path: Path):
    pcap = build_tls_sni_pcap(
        tmp_path / "empty.pcap",
        client_hello=build_client_hello(""),
    )
    result = _analyse(pcap, tmp_path, "empty")
    assert result.packets > 0
    assert _sni_findings(result) == []
    assert _sni_iocs(result) == []


def test_truncated_clienthello_pcap_does_not_crash(tmp_path: Path):
    hello = build_client_hello(TLS_SNI_HOST)
    pcap = build_tls_sni_pcap(tmp_path / "trunc.pcap", client_hello=hello[:12])
    result = _analyse(pcap, tmp_path, "trunc")
    assert result.packets > 0
    assert _sni_findings(result) == []
    assert TLS_SNI_HOST not in _sni_iocs(result)
