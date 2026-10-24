"""Safe streaming PCAP reader with size and count limits.

Packet captures are untrusted input. A PCAP file is just a magic number,
then a list of (header, bytes) records. The header's `incl_len` field is
how many bytes the next record claims to hold — a hostile file can put
2 GiB there. This module never passes a length from the file to read()
or to an allocator until it has been checked against the remaining file
size and ParseLimits.
"""
from __future__ import annotations

import logging
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scapy.all import IP, Ether
from scapy.config import conf as scapy_conf
from scapy.layers.dns import DNS
from scapy.utils import PcapNgReader

# Scapy prints "WARNING: ..." to the terminal on bad DNS / PCAPng. The CLI
# already reports a single clear error; keep the dissector quiet.
scapy_conf.verb = 0
logging.getLogger("scapy").setLevel(logging.ERROR)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Importing DNS registers "UDP port 53 → DNS" so valid queries still
# dissect after we stopped using scapy's rdpcap(). The binding below
# keeps the import live for linters.
_REGISTER_DNS = DNS

# On-disk magic numbers. Classic pcap stores the magic in *file* byte
# order, so little-endian and big-endian captures look different here.
MAGIC_LE_USEC = b"\xd4\xc3\xb2\xa1"
MAGIC_BE_USEC = b"\xa1\xb2\xc3\xd4"
MAGIC_LE_NSEC = b"\x4d\x3c\xb2\xa1"
MAGIC_BE_NSEC = b"\xa1\xb2\x3c\x4d"
MAGIC_PCAPNG = b"\x0a\x0d\x0d\x0a"

_CLASSIC_LE = {MAGIC_LE_USEC, MAGIC_LE_NSEC}
_CLASSIC_BE = {MAGIC_BE_USEC, MAGIC_BE_NSEC}
_NSEC = {MAGIC_LE_NSEC, MAGIC_BE_NSEC}

# DLT_EN10MB = Ethernet II (what tcpdump writes by default).
# DLT_RAW = a bare IPv4/IPv6 packet with no Ethernet header.
# Any other link type is still attempted as Ethernet so a rare DLT
# does not crash the process.
DLT_EN10MB = 1
DLT_RAW = 101


class PcapParseError(ValueError):
    """Malformed, truncated, or oversized PCAP. Safe to show on the CLI."""


@dataclass(frozen=True)
class ParseLimits:
    """Upper bounds so a hostile capture cannot exhaust memory or hang.

    Defaults are sized for a SOC laptop doing offline triage:
    - 512 MiB / 250_000 packets: a large capture that still fits in RAM
    - 256 KiB per packet: the common 262144-byte max snaplen, but not a
      lying 2 GiB incl_len
    - 8 MiB per TCP stream / 4 MiB HTTP body: enough for a sample
      download, not a multi-GB transfer held in memory
    """

    max_file_bytes: int = 512 * 1024 * 1024
    max_packets: int = 250_000
    max_packet_bytes: int = 256 * 1024
    max_stream_bytes: int = 8 * 1024 * 1024
    max_http_body_bytes: int = 4 * 1024 * 1024
    max_http_header_bytes: int = 64 * 1024
    max_http_messages: int = 1_000
    max_dns_name_bytes: int = 255


DEFAULT_LIMITS = ParseLimits()


def iter_packets(
    path: str | Path, limits: ParseLimits | None = None
) -> Iterator[Any]:
    """Yield dissected packets from `path`, streaming from disk.

    Raises PcapParseError on a truncated header, a lying incl_len, an
    unrecognised file type, or a limit breach. Individual packets that
    fail to dissect are skipped so one bad frame does not abort an
    otherwise readable capture.
    """
    limits = limits or DEFAULT_LIMITS
    path = Path(path)
    if not path.exists():
        raise PcapParseError(f"PCAP not found: {path}")
    if not path.is_file():
        raise PcapParseError(f"PCAP path is not a regular file: {path}")

    size = path.stat().st_size
    if size < 4:
        raise PcapParseError("PCAP is truncated (shorter than a 4-byte magic number)")
    if size > limits.max_file_bytes:
        raise PcapParseError(
            f"PCAP is {size:,} bytes; exceeds the "
            f"{limits.max_file_bytes:,} byte file-size limit"
        )

    with path.open("rb") as fh:
        magic = fh.read(4)
    if magic in _CLASSIC_LE or magic in _CLASSIC_BE:
        yield from _iter_classic_pcap(path, limits, size)
        return
    if magic == MAGIC_PCAPNG:
        yield from _iter_pcapng(path, limits)
        return
    raise PcapParseError("not a PCAP or PCAPng file (unrecognised magic)")


def load_packets(path: str | Path, limits: ParseLimits | None = None) -> list[Any]:
    """Read a bounded list of packets. Empty captures are an error.

    Packets are streamed off disk (we never mmap or slurp the file),
    then kept in a list of at most ``limits.max_packets`` frames so the
    later multi-pass detections have something to walk.
    """
    packets = list(iter_packets(path, limits))
    if not packets:
        raise PcapParseError("PCAP contains no packets")
    return packets


def _iter_classic_pcap(path: Path, limits: ParseLimits, size: int) -> Iterator[Any]:
    """Parse a classic libpcap file one record at a time."""
    with path.open("rb") as fh:
        hdr = fh.read(24)
        if len(hdr) < 24:
            raise PcapParseError("PCAP is truncated (incomplete global header)")
        magic = hdr[:4]
        endian = "<" if magic in _CLASSIC_LE else ">"
        nsec = magic in _NSEC
        _maj, _min, _zone, _sigs, snaplen, network = struct.unpack(
            endian + "HHIIII", hdr[4:]
        )
        if snaplen == 0:
            raise PcapParseError("PCAP global header has snaplen 0 (invalid)")

        dissect = IP if network == DLT_RAW else Ether
        count = 0
        while True:
            phdr = fh.read(16)
            if not phdr:
                break
            if len(phdr) < 16:
                raise PcapParseError("PCAP is truncated (incomplete packet header)")
            ts_sec, ts_sub, incl_len, _orig_len = struct.unpack(endian + "IIII", phdr)
            # Bound the claimed capture length *before* reading payload.
            if incl_len > limits.max_packet_bytes:
                raise PcapParseError(
                    f"packet {count + 1} claims incl_len={incl_len:,} bytes; "
                    f"exceeds the {limits.max_packet_bytes:,} byte packet-size limit"
                )
            remaining = size - fh.tell()
            if incl_len > remaining:
                raise PcapParseError(
                    f"PCAP is truncated (packet {count + 1} promised "
                    f"{incl_len} bytes, {remaining} remain in the file)"
                )
            data = fh.read(incl_len)
            if len(data) < incl_len:
                raise PcapParseError(
                    f"PCAP is truncated (packet {count + 1} promised "
                    f"{incl_len} bytes, got {len(data)})"
                )
            count += 1
            if count > limits.max_packets:
                raise PcapParseError(
                    f"PCAP exceeds the {limits.max_packets:,} packet count limit"
                )
            if not data:
                continue
            pkt = _dissect(dissect, data)
            if pkt is None:
                continue
            denom = 1_000_000_000.0 if nsec else 1_000_000.0
            pkt.time = float(ts_sec) + float(ts_sub) / denom
            yield pkt


def _iter_pcapng(path: Path, limits: ParseLimits) -> Iterator[Any]:
    """PCAPng path: file size is already capped; still bound each packet."""
    count = 0
    try:
        reader = PcapNgReader(str(path))
    except Exception as exc:
        raise PcapParseError("PCAPng file is truncated or corrupt") from exc
    try:
        for pkt in reader:
            count += 1
            if count > limits.max_packets:
                raise PcapParseError(
                    f"PCAP exceeds the {limits.max_packets:,} packet count limit"
                )
            caplen = int(getattr(pkt, "wirelen", 0) or 0)
            if caplen > limits.max_packet_bytes:
                raise PcapParseError(
                    f"packet {count} is {caplen:,} bytes; "
                    f"exceeds the {limits.max_packet_bytes:,} byte packet-size limit"
                )
            yield pkt
    except PcapParseError:
        raise
    except RecursionError as exc:
        raise PcapParseError("malformed PCAPng caused parser recursion") from exc
    except Exception as exc:
        raise PcapParseError(f"failed to parse PCAPng: {exc}") from exc
    finally:
        close = getattr(reader, "close", None)
        if close is not None:
            close()


def _dissect(cls: type, data: bytes) -> Any:
    """Dissect one frame. Recursion is a parse error; anything else is skip."""
    try:
        return cls(data)
    except RecursionError as exc:
        raise PcapParseError("malformed packet caused parser recursion") from exc
    except Exception:
        return None
