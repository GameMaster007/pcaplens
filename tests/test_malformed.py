"""Robustness tests: malformed / untrusted PCAPs must fail closed.

The corpus is generated in-process (see malformed_corpus.py). The huge
capture is built at test time so we never commit a large binary.
"""
from __future__ import annotations

import random
import struct
from pathlib import Path

import pytest
from tests.malformed_corpus import (
    pcap_global_header,
    small_corpus,
    write_bogus_incl_len,
    write_huge_pcap,
    write_malformed_dns,
    write_malformed_http,
    write_many_tiny_packets,
    write_truncated_packet,
)

from pcaplens.analyze import analyze_pcap, parse_http
from pcaplens.cli import main
from pcaplens.parse import ParseLimits, PcapParseError

# Structural problems the reader must refuse. Application-layer junk
# (malformed DNS/HTTP) is a skip-and-continue case, not a hard error.
_MUST_REJECT = (
    "truncated_header",
    "truncated_packet",
    "bogus_incl_len",
    "bogus_snaplen",
    "empty",
    "garbage",
)


@pytest.fixture
def corpus(tmp_path: Path) -> dict[str, Path]:
    return small_corpus(tmp_path / "corpus")


def _analyse(pcap: Path, tmp_path: Path, limits: ParseLimits | None = None):
    return analyze_pcap(
        pcap,
        case_id="FUZZ",
        examiner="pytest",
        out=tmp_path / "out",
        tshark_cross_check=False,
        limits=limits,
    )


def test_corpus_files_are_tiny(corpus: dict[str, Path]):
    """Committed-style fixtures stay small; nothing here is a multi-MB blob."""
    for name, path in corpus.items():
        assert path.is_file(), name
        assert path.stat().st_size < 16_384, name


@pytest.mark.parametrize("name", _MUST_REJECT)
def test_structural_malformed_pcaps_raise_parse_error(
    corpus: dict[str, Path], tmp_path: Path, name: str
):
    with pytest.raises(PcapParseError):
        _analyse(corpus[name], tmp_path / name)


def test_malformed_dns_does_not_raise(corpus: dict[str, Path], tmp_path: Path):
    result = _analyse(corpus["malformed_dns"], tmp_path / "dns")
    assert result.packets >= 1


def test_malformed_http_does_not_raise(corpus: dict[str, Path], tmp_path: Path):
    result = _analyse(corpus["malformed_http"], tmp_path / "http")
    assert result.packets >= 1


def test_parse_http_invalid_content_length():
    data = b"GET / HTTP/1.1\r\nHost: a.example\r\nContent-Length: nope\r\n\r\nxx"
    msgs = parse_http(data)
    assert isinstance(msgs, list)
    assert msgs, "one HTTP message should still be returned"
    # Invalid Content-Length is treated as 0, not as a crash or a huge read.
    assert msgs[0][2] == b""


def test_parse_http_huge_declared_length_is_capped():
    data = b"GET / HTTP/1.1\r\nContent-Length: 999999999\r\n\r\nshort"
    msgs = parse_http(data)
    assert len(msgs) == 1
    assert msgs[0][2] == b"short"


def test_parse_http_never_raises_on_random_payloads():
    rng = random.Random(20261024)
    for _ in range(40):
        blob = rng.randbytes(rng.randint(0, 400))
        assert isinstance(parse_http(blob), list)


def test_huge_capture_generated_at_test_time(tmp_path: Path):
    """A ~1 MiB capture is built here (not stored in git) and hits the cap."""
    pcap = write_huge_pcap(tmp_path / "huge.pcap", min_bytes=1_048_576)
    assert pcap.stat().st_size >= 1_048_576
    limits = ParseLimits(max_file_bytes=256_000)
    with pytest.raises(PcapParseError, match="limit|exceeds"):
        _analyse(pcap, tmp_path / "huge_out", limits=limits)


def test_packet_count_limit(tmp_path: Path):
    pcap = write_many_tiny_packets(tmp_path / "many.pcap", count=80)
    limits = ParseLimits(max_packets=40)
    with pytest.raises(PcapParseError, match="packet"):
        _analyse(pcap, tmp_path / "many_out", limits=limits)


def test_bogus_incl_len_does_not_hang(tmp_path: Path):
    """A 2 GiB claimed length must be rejected without reading that far."""
    pcap = write_bogus_incl_len(tmp_path / "lie.pcap")
    assert pcap.stat().st_size < 100
    with pytest.raises(PcapParseError):
        _analyse(pcap, tmp_path / "lie_out")


def test_cli_malformed_pcap_fails_safely(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    pcap = write_truncated_packet(tmp_path / "trunc.pcap")
    rc = main(
        ["analyse", str(pcap), "--out", str(tmp_path / "cli_out"), "--no-tshark"]
    )
    captured = capsys.readouterr()
    assert rc != 0
    assert "error:" in captured.err.lower()
    assert "Traceback" not in captured.err
    assert "Traceback" not in captured.out


def test_cli_malformed_dns_exits_zero(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    pcap = write_malformed_dns(tmp_path / "dns.pcap")
    rc = main(
        ["analyse", str(pcap), "--out", str(tmp_path / "cli_dns"), "--no-tshark"]
    )
    captured = capsys.readouterr()
    assert rc == 0
    assert "Traceback" not in captured.err


def test_cli_malformed_http_exits_zero(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    pcap = write_malformed_http(tmp_path / "http.pcap")
    rc = main(
        ["analyse", str(pcap), "--out", str(tmp_path / "cli_http"), "--no-tshark"]
    )
    captured = capsys.readouterr()
    assert rc == 0
    assert "Traceback" not in captured.err


def test_fuzz_random_buffers_fail_closed(tmp_path: Path):
    """Small property-style loop: random buffers never escape as exceptions."""
    rng = random.Random(42)
    header = pcap_global_header()
    tight = ParseLimits(max_file_bytes=8_192, max_packets=32, max_packet_bytes=512)
    for i in range(24):
        if i % 3 == 0:
            blob = rng.randbytes(rng.randint(0, 300))
        elif i % 3 == 1:
            blob = header + rng.randbytes(rng.randint(0, 300))
        else:
            # Valid header + a packet header whose incl_len is a random uint32.
            incl = rng.randrange(0, 2**32)
            pkt_hdr = struct.pack(
                "<IIII",
                rng.randrange(2**16),
                rng.randrange(2**16),
                incl,
                incl,
            )
            blob = header + pkt_hdr + rng.randbytes(rng.randint(0, 80))
        path = tmp_path / f"fuzz_{i}.pcap"
        path.write_bytes(blob)
        try:
            analyze_pcap(
                path,
                case_id="FUZZ",
                examiner="pytest",
                out=tmp_path / f"fuzz_out_{i}",
                tshark_cross_check=False,
                limits=tight,
            )
        except PcapParseError:
            pass
