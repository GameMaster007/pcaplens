"""Large synthetic captures stay time- and memory-bounded."""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from malformed_corpus import write_many_tiny_packets
from pcaplens.analyze import analyze_pcap
from pcaplens.ingest import ingest_capture
from pcaplens.parse import ParseLimits, PcapParseError, iter_packets

_ONE_MILLION = 1_000_000


def _rss_bytes() -> int:
    status = Path("/proc/self/status")
    if not status.is_file():
        return 0
    for line in status.read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) * 1024
    return 0


def test_default_limit_rejects_oversized_packet_count(tmp_path: Path):
    pcap = write_many_tiny_packets(tmp_path / "over.pcap", count=1_000)
    with pytest.raises(PcapParseError, match="packet count"):
        analyze_pcap(
            pcap,
            out=tmp_path / "out",
            tshark_cross_check=False,
            limits=ParseLimits(max_packets=200),
        )


def test_stream_one_million_packets_is_bounded(tmp_path: Path):
    """~1M frames: stream once, do not keep the list, finish in CI time."""
    pcap = write_many_tiny_packets(tmp_path / "1m.pcap", count=_ONE_MILLION)
    limits = ParseLimits(max_packets=_ONE_MILLION, max_file_bytes=200 * 1024 * 1024)
    before = _rss_bytes()
    t0 = time.monotonic()
    n = 0
    for _pkt in iter_packets(pcap, limits):
        n += 1
    elapsed = time.monotonic() - t0
    after = _rss_bytes()
    assert n == _ONE_MILLION
    assert elapsed < 90.0
    if before and after:
        # Streaming must not grow by the size of 1M Scapy packets (~GBs).
        assert after - before < 512 * 1024 * 1024


def test_ingest_does_not_retain_scapy_packets(tmp_path: Path):
    pcap = write_many_tiny_packets(tmp_path / "8k.pcap", count=8_000)
    limits = ParseLimits(max_packets=8_000, max_file_bytes=8 * 1024 * 1024)
    view = ingest_capture(pcap, limits)
    assert view.packet_count == 8_000
    assert view.streams == {}
    assert isinstance(view.tcp, list)
