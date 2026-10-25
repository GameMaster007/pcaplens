"""Seeded fuzz: parsers must not crash, hang, or honour lying lengths."""
from __future__ import annotations

import random
import time
from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from malformed_corpus import (
    pcap_global_header,
    pcap_record,
    tiny_frame,
    write_pcapng,
    write_sll_pcap,
)
from pcaplens.analyze import analyze_pcap, parse_http, reassemble
from pcaplens.dns_analysis import analyze_dns
from pcaplens.parse import ParseLimits, PcapParseError, iter_packets, load_packets
from pcaplens.tls import extract_sni

_SEEDS = (1, 7, 13, 42, 99, 255, 1024, 20261025)
_TIGHT = ParseLimits(max_file_bytes=16_384, max_packets=64, max_packet_bytes=1_024)


def _safe_analyse(path: Path, out: Path) -> None:
    try:
        analyze_pcap(
            path,
            case_id="FUZZ",
            examiner="pytest",
            out=out,
            tshark_cross_check=False,
            limits=_TIGHT,
        )
    except (PcapParseError, FileNotFoundError, ValueError):
        return


def _mutate(blob: bytes, rng: random.Random) -> bytes:
    if not blob:
        return rng.randbytes(rng.randint(0, 40))
    style = rng.choice(("truncate", "bitflip", "insert", "repeat", "overwrite"))
    raw = bytearray(blob)
    if style == "truncate":
        return bytes(raw[: rng.randrange(len(raw) + 1)])
    if style == "bitflip":
        for _ in range(rng.randint(1, 8)):
            raw[rng.randrange(len(raw))] ^= 1 << rng.randrange(8)
        return bytes(raw)
    if style == "insert":
        i = rng.randrange(len(raw) + 1)
        raw[i:i] = rng.randbytes(rng.randint(1, 16))
        return bytes(raw)
    if style == "repeat":
        return bytes(raw) * rng.randint(0, 3)
    i = rng.randrange(len(raw))
    n = min(len(raw) - i, rng.randint(1, 16))
    raw[i : i + n] = rng.randbytes(n)
    return bytes(raw)


@pytest.mark.parametrize("seed", _SEEDS)
def test_fuzz_classic_and_pcapng_fail_closed(tmp_path: Path, seed: int):
    rng = random.Random(seed)
    bases = [
        pcap_global_header() + pcap_record(tiny_frame()),
        pcap_global_header(endian=">") + pcap_record(tiny_frame(), endian=">"),
        pcap_global_header(nsec=True) + pcap_record(tiny_frame()),
        pcap_global_header(network=113) + pcap_record(tiny_frame()),
        pcap_global_header(network=276) + pcap_record(tiny_frame()),
        pcap_global_header(network=101) + pcap_record(tiny_frame()),
        write_pcapng(tmp_path / f"base_{seed}.pcapng").read_bytes(),
    ]
    out = tmp_path / "out"
    t0 = time.monotonic()
    for i in range(12):
        blob = _mutate(rng.choice(bases), rng)
        path = tmp_path / f"m_{seed}_{i}.pcap"
        path.write_bytes(blob)
        _safe_analyse(path, out)
    assert time.monotonic() - t0 < 8.0


@pytest.mark.parametrize("seed", _SEEDS)
def test_fuzz_sll_and_sll2_fail_closed(tmp_path: Path, seed: int):
    rng = random.Random(seed)
    bases = [
        write_sll_pcap(tmp_path / f"sll1_{seed}.pcap", version=1, ipv6=False).read_bytes(),
        write_sll_pcap(tmp_path / f"sll2_{seed}.pcap", version=2, ipv6=False).read_bytes(),
        write_sll_pcap(tmp_path / f"sll16_{seed}.pcap", version=1, ipv6=True).read_bytes(),
        write_sll_pcap(tmp_path / f"sll26_{seed}.pcap", version=2, ipv6=True).read_bytes(),
    ]
    out = tmp_path / "out"
    for i in range(10):
        path = tmp_path / f"sll_{seed}_{i}.pcap"
        path.write_bytes(_mutate(rng.choice(bases), rng))
        _safe_analyse(path, out)
        try:
            list(iter_packets(path, _TIGHT))
        except PcapParseError:
            pass


@pytest.mark.parametrize("seed", _SEEDS)
def test_fuzz_http_and_tls_never_raise(seed: int):
    rng = random.Random(seed)
    hello = (
        b"\x16\x03\x03\x00\x20"
        + b"\x01\x00\x00\x1c"
        + b"\x03\x03"
        + bytes(range(32))[:32]
    )
    for _ in range(20):
        blob = _mutate(rng.choice((hello, b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", b"")), rng)
        blob += rng.randbytes(rng.randint(0, 80))
        sni = extract_sni(blob)
        assert sni is None or isinstance(sni, str)
        assert isinstance(parse_http(blob), list)


@pytest.mark.parametrize("seed", _SEEDS)
def test_fuzz_dns_module_never_raises(seed: int):
    rng = random.Random(seed)
    pkts = []
    for _ in range(8):
        payload = rng.randbytes(rng.randint(0, 120))
        pkt = Ether() / IP(src="10.10.0.21", dst="10.10.0.1") / UDP(
            sport=rng.randrange(1024, 65535), dport=53
        ) / Raw(payload)
        pkt.time = 1.0
        pkts.append(pkt)
    findings, events, iocs = analyze_dns(pkts, max_name_bytes=255)
    assert isinstance(findings, list)
    assert isinstance(events, list)
    assert isinstance(iocs, list)


def test_fuzz_tls_tiny_records_do_not_walk_forever():
    """8 KiB of 5-byte handshake headers must return quickly."""
    blob = b"\x16\x03\x03\x00\x00" * 2000
    t0 = time.monotonic()
    assert extract_sni(blob) is None
    assert time.monotonic() - t0 < 0.25


def test_fuzz_reassemble_random_payloads():
    rng = random.Random(99)
    pkts = []
    for i in range(20):
        pkt = IP(src="10.10.0.1", dst="10.10.0.2") / TCP(
            sport=40000,
            dport=80,
            flags="PA",
            seq=rng.randrange(1, 1000),
        ) / Raw(rng.randbytes(rng.randint(0, 40)))
        pkt.time = float(i)
        pkts.append(pkt)
    streams, first = reassemble(pkts, max_stream_bytes=256)
    assert isinstance(streams, dict)
    assert isinstance(first, dict)


def test_lying_incl_len_rejected_quickly(tmp_path: Path):
    blob = pcap_global_header() + pcap_record(b"xxxx", incl_len=0x7FFFFFFF, orig_len=0x7FFFFFFF)
    path = tmp_path / "lie.pcap"
    path.write_bytes(blob)
    t0 = time.monotonic()
    with pytest.raises(PcapParseError):
        load_packets(path, _TIGHT)
    assert time.monotonic() - t0 < 0.5
