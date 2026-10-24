"""TLS ClientHello SNI extraction (issue #1)."""
from __future__ import annotations

from pathlib import Path

import pytest

from pcaplens.analyze import analyze_pcap
from pcaplens.synth import TLS_SNI_HOST, build_client_hello, build_tls_sni_pcap
from pcaplens.tls import extract_sni


def test_extract_sni_from_bytes():
    assert extract_sni(build_client_hello(TLS_SNI_HOST)) == TLS_SNI_HOST


def test_extract_sni_missing_extension():
    assert extract_sni(build_client_hello(None)) is None


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
    result = analyze_pcap(
        pcap,
        case_id="TEST-SNI",
        examiner="pytest",
        out=tmp_path / "out_sni",
        tshark_cross_check=False,
    )
    assert any(
        title == "TLS SNI" and TLS_SNI_HOST in detail
        for _, title, detail in result.findings
    )
    assert any(
        kind == "domain" and value == TLS_SNI_HOST
        for kind, value, _ in result.iocs
    )
    report = result.report_path.read_text(encoding="utf-8")
    assert TLS_SNI_HOST in report


def test_truncated_clienthello_pcap_does_not_crash(tmp_path: Path):
    hello = build_client_hello(TLS_SNI_HOST)
    pcap = build_tls_sni_pcap(
        tmp_path / "trunc.pcap",
        client_hello=hello[:12],
    )
    result = analyze_pcap(
        pcap,
        case_id="TEST-SNI-TRUNC",
        examiner="pytest",
        out=tmp_path / "out_trunc",
        tshark_cross_check=False,
    )
    assert result.packets > 0
    assert not any(title == "TLS SNI" for _, title, _ in result.findings)
    assert not any(value == TLS_SNI_HOST for _, value, _ in result.iocs)
