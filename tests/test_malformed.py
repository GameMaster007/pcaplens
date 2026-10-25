"""Robustness tests: malformed / untrusted PCAPs must fail closed.

The corpus is generated in-process (see malformed_corpus.py). The huge
capture is built at test time so we never commit a large binary.
"""
from __future__ import annotations

import random
import struct
from pathlib import Path

import pytest

from malformed_corpus import (
    pcap_global_header,
    pcap_record,
    small_corpus,
    tiny_frame,
    write_bogus_incl_len,
    write_huge_pcap,
    write_malformed_dns,
    write_malformed_http,
    write_many_tiny_packets,
    write_pcapng,
    write_pcapng_lying_block_length,
    write_pcapng_snaplen_truncated,
    write_raw_ipv6_pcap,
    write_sll_pcap,
    write_snaplen_truncated_pcap,
    write_truncated_packet,
    write_truncated_pcapng,
    write_valid_tiny_pcap,
)
from pcaplens.analyze import analyze_pcap, parse_http, reassemble
from pcaplens.cli import main
from pcaplens.parse import ParseLimits, PcapParseError, iter_packets, load_packets

# Structural problems the reader must refuse. Application-layer junk
# (malformed DNS/HTTP) is a skip-and-continue case, not a hard error.
_MUST_REJECT = (
    "truncated_header",
    "truncated_packet",
    "incomplete_packet_header",
    "bogus_incl_len",
    "bogus_snaplen",
    "empty",
    "empty_file",
    "zero_length_packet",
    "garbage",
    "truncated_pcapng",
    "pcapng_lying_block",
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


def test_parse_http_negative_content_length():
    data = b"GET / HTTP/1.1\r\nContent-Length: -5\r\n\r\nxxxxx"
    msgs = parse_http(data)
    assert msgs
    assert msgs[0][2] == b""


def test_parse_http_overlong_digit_string_is_ignored():
    # 40 digits would become a huge int if we called int() blindly.
    data = b"GET / HTTP/1.1\r\nContent-Length: " + b"9" * 40 + b"\r\n\r\nshort"
    msgs = parse_http(data)
    assert msgs
    assert msgs[0][2] == b""


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
    assert "WARNING" not in captured.err


def test_cli_truncated_pcapng_is_quiet(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    pcap = write_truncated_pcapng(tmp_path / "t.pcapng")
    rc = main(
        ["analyse", str(pcap), "--out", str(tmp_path / "cli_ng"), "--no-tshark"]
    )
    captured = capsys.readouterr()
    assert rc != 0
    assert "error:" in captured.err.lower()
    assert "WARNING" not in captured.err
    assert "Traceback" not in captured.err


def test_cli_malformed_dns_exits_zero(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    pcap = write_malformed_dns(tmp_path / "dns.pcap")
    rc = main(
        ["analyse", str(pcap), "--out", str(tmp_path / "cli_dns"), "--no-tshark"]
    )
    captured = capsys.readouterr()
    assert rc == 0
    assert "Traceback" not in captured.err
    assert "WARNING" not in captured.err


def test_cli_malformed_http_exits_zero(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    pcap = write_malformed_http(tmp_path / "http.pcap")
    rc = main(
        ["analyse", str(pcap), "--out", str(tmp_path / "cli_http"), "--no-tshark"]
    )
    captured = capsys.readouterr()
    assert rc == 0
    assert "Traceback" not in captured.err
    assert "WARNING" not in captured.err


def test_cli_missing_file_fails_safely(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    rc = main(
        [
            "analyse",
            str(tmp_path / "no-such.pcap"),
            "--out",
            str(tmp_path / "cli_missing"),
            "--no-tshark",
        ]
    )
    captured = capsys.readouterr()
    assert rc != 0
    assert "error:" in captured.err.lower()
    assert "not found" in captured.err.lower()
    assert "Traceback" not in captured.err


def test_cli_directory_fails_safely(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    folder = tmp_path / "not-a-file"
    folder.mkdir()
    rc = main(
        ["analyse", str(folder), "--out", str(tmp_path / "cli_dir"), "--no-tshark"]
    )
    captured = capsys.readouterr()
    assert rc != 0
    assert "error:" in captured.err.lower()
    assert "regular file" in captured.err.lower()
    assert "Traceback" not in captured.err


def test_missing_pcap_raises(tmp_path: Path):
    with pytest.raises(PcapParseError, match="not found"):
        _analyse(tmp_path / "nope.pcap", tmp_path / "missing_out")


def test_directory_is_not_a_pcap(tmp_path: Path):
    folder = tmp_path / "dir"
    folder.mkdir()
    with pytest.raises(PcapParseError, match="not a regular file"):
        _analyse(folder, tmp_path / "dir_out")


def test_big_endian_pcap_is_readable(tmp_path: Path):
    pcap = write_valid_tiny_pcap(tmp_path / "be.pcap", endian=">")
    result = _analyse(pcap, tmp_path / "be_out")
    assert result.packets >= 1


def test_nsec_magic_pcap_is_readable(tmp_path: Path):
    pcap = write_valid_tiny_pcap(tmp_path / "nsec.pcap", nsec=True)
    result = _analyse(pcap, tmp_path / "nsec_out")
    assert result.packets >= 1


def test_pcapng_is_readable(tmp_path: Path):
    pcap = write_pcapng(tmp_path / "ok.pcapng")
    result = _analyse(pcap, tmp_path / "ng_out")
    assert result.packets >= 1


def test_pcapng_lying_block_length_does_not_allocate(tmp_path: Path):
    """A 120-byte PCAPng that claims a 2.1 GiB block must fail closed quickly."""
    pcap = write_pcapng_lying_block_length(tmp_path / "lie120.pcapng", size=120)
    assert pcap.stat().st_size == 120
    with pytest.raises(PcapParseError, match="remain"):
        _analyse(pcap, tmp_path / "lie120_out")


def test_packet_size_limit_uses_captured_not_wire_length(tmp_path: Path):
    """orig_len / wirelen is 9000; captured bytes are a normal frame."""
    limits = ParseLimits(max_packet_bytes=256)
    classic = write_snaplen_truncated_pcap(tmp_path / "snap.pcap", orig_len=9000)
    result = _analyse(classic, tmp_path / "snap_out", limits=limits)
    assert result.packets >= 1
    ng = write_pcapng_snaplen_truncated(tmp_path / "snap.pcapng", orig_len=9000)
    result_ng = _analyse(ng, tmp_path / "snap_ng_out", limits=limits)
    assert result_ng.packets >= 1


def test_retransmits_do_not_consume_stream_size_cap():
    from scapy.layers.inet import IP, TCP
    from scapy.packet import Raw

    first = IP(src="10.10.0.21", dst="198.51.100.10") / TCP(
        sport=40000, dport=80, flags="PA", seq=1
    ) / Raw(b"A" * 60)
    retx = IP(src="10.10.0.21", dst="198.51.100.10") / TCP(
        sport=40000, dport=80, flags="PA", seq=1
    ) / Raw(b"A" * 60)
    nxt = IP(src="10.10.0.21", dst="198.51.100.10") / TCP(
        sport=40000, dport=80, flags="PA", seq=61
    ) / Raw(b"B" * 40)
    # Ten retransmits of the first 60 bytes would exhaust a 100-byte cap
    # if seq were not deduped, dropping the unique 40-byte segment.
    streams, _ = reassemble(
        [first, *[retx] * 10, nxt],
        max_stream_bytes=100,
    )
    key = ("10.10.0.21", 40000, "198.51.100.10", 80)
    assert key in streams
    assert streams[key] == (b"A" * 60) + (b"B" * 40)


def test_linux_sll_and_sll2_decode_ipv4_and_ipv6(tmp_path: Path):
    from scapy.all import IP, IPv6

    cases = (
        write_sll_pcap(tmp_path / "sll4.pcap", version=1, ipv6=False),
        write_sll_pcap(tmp_path / "sll2_4.pcap", version=2, ipv6=False),
        write_sll_pcap(tmp_path / "sll6.pcap", version=1, ipv6=True),
        write_sll_pcap(tmp_path / "sll2_6.pcap", version=2, ipv6=True),
        write_raw_ipv6_pcap(tmp_path / "raw6.pcap"),
    )
    for path in cases:
        pkts = load_packets(path)
        assert pkts, path.name
        pkt = pkts[0]
        if "6" in path.name or path.name.startswith("raw"):
            assert IPv6 in pkt, path.name
        else:
            assert IP in pkt, path.name
            assert pkt[IP].src == "10.10.0.21"


def test_iter_packets_streams(tmp_path: Path):
    pcap = write_many_tiny_packets(tmp_path / "stream.pcap", count=5)
    it = iter_packets(pcap)
    assert hasattr(it, "__next__")
    first = next(it)
    assert first is not None


def test_truncate_valid_pcap_at_every_offset(tmp_path: Path):
    """Cutting a good file at every byte must fail closed, never crash."""
    full = pcap_global_header() + pcap_record(tiny_frame())
    tight = ParseLimits(max_file_bytes=8_192, max_packets=32, max_packet_bytes=512)
    out = tmp_path / "trunc_out"
    for n in range(len(full)):
        path = tmp_path / f"cut_{n}.pcap"
        path.write_bytes(full[:n])
        try:
            analyze_pcap(
                path,
                case_id="FUZZ",
                examiner="pytest",
                out=out,
                tshark_cross_check=False,
                limits=tight,
            )
        except PcapParseError:
            pass


def test_fuzz_random_buffers_fail_closed(tmp_path: Path):
    """Property-style loop: several seeds and mutation styles, fail closed."""
    valid_le = pcap_global_header() + pcap_record(tiny_frame())
    valid_be = pcap_global_header(endian=">") + pcap_record(tiny_frame(), endian=">")
    valid_nsec = pcap_global_header(nsec=True) + pcap_record(tiny_frame())
    pcapng_magic = b"\x0a\x0d\x0d\x0a"
    tight = ParseLimits(max_file_bytes=8_192, max_packets=32, max_packet_bytes=512)
    out = tmp_path / "fuzz_out"
    styles = (
        "random",
        "le_header",
        "be_header",
        "nsec_header",
        "pcapng_header",
        "bitflip",
        "truncate",
        "incl_len",
        "short_phdr",
    )
    for seed in (1, 7, 42, 99, 20261024):
        rng = random.Random(seed)
        for style in styles:
            if style == "random":
                blob = rng.randbytes(rng.randint(0, 300))
            elif style == "le_header":
                blob = pcap_global_header() + rng.randbytes(rng.randint(0, 200))
            elif style == "be_header":
                blob = pcap_global_header(endian=">") + rng.randbytes(rng.randint(0, 200))
            elif style == "nsec_header":
                blob = pcap_global_header(nsec=True) + rng.randbytes(rng.randint(0, 200))
            elif style == "pcapng_header":
                blob = pcapng_magic + rng.randbytes(rng.randint(0, 200))
            elif style == "bitflip":
                raw = bytearray(rng.choice((valid_le, valid_be, valid_nsec)))
                if raw:
                    raw[rng.randrange(len(raw))] ^= 1 << rng.randrange(8)
                blob = bytes(raw)
            elif style == "truncate":
                src = rng.choice((valid_le, valid_be, valid_nsec))
                blob = src[: rng.randrange(len(src) + 1)]
            elif style == "incl_len":
                incl = rng.randrange(0, 2**32)
                pkt_hdr = struct.pack(
                    "<IIII",
                    rng.randrange(2**16),
                    rng.randrange(2**16),
                    incl,
                    incl,
                )
                blob = pcap_global_header() + pkt_hdr + rng.randbytes(rng.randint(0, 80))
            elif style == "short_phdr":
                blob = pcap_global_header() + rng.randbytes(rng.randint(1, 15))
            else:
                raise AssertionError(f"unknown style {style}")
            path = tmp_path / "fuzz.pcap"
            path.write_bytes(blob)
            try:
                analyze_pcap(
                    path,
                    case_id="FUZZ",
                    examiner="pytest",
                    out=out,
                    tshark_cross_check=False,
                    limits=tight,
                )
            except PcapParseError:
                pass
