"""Safe streaming PCAP reader with size and count limits.

Packet captures are untrusted input. Length fields in the file are never
passed to a read() or used to allocate until they have been checked
against the remaining file size and ParseLimits.
"""
from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from scapy.all import DNS, IP, Ether  # noqa: F401  # DNS import registers the dissector
from scapy.utils import PcapNgReader

# Classic libpcap magic (on-disk bytes) and PCAPng section-header block.
MAGIC_LE_USEC = b"\xd4\xc3\xb2\xa1"
MAGIC_BE_USEC = b"\xa1\xb2\xc3\xd4"
MAGIC_LE_NSEC = b"\x4d\x3c\xb2\xa1"
MAGIC_BE_NSEC = b"\xa1\xb2\x3c\x4d"
MAGIC_PCAPNG = b"\x0a\x0d\x0d\x0a"

_CLASSIC_LE = {MAGIC_LE_USEC, MAGIC_LE_NSEC}
_CLASSIC_BE = {MAGIC_BE_USEC, MAGIC_BE_NSEC}
_NSEC = {MAGIC_LE_NSEC, MAGIC_BE_NSEC}

# Link-layer types we dissect ourselves. Anything else is still attempted
# as Ethernet so a rare DLT does not crash the process.
DLT_EN10MB = 1
DLT_RAW = 101


class PcapParseError(ValueError):
    """Malformed, truncated, or oversized PCAP. Safe to show on the CLI."""


@dataclass(frozen=True)
class ParseLimits:
    """Upper bounds so a hostile capture cannot exhaust memory or hang."""

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
) -> Iterator:
    """Yield dissected packets from `path`, streaming from disk.

    Raises PcapParseError on a truncated header, a lying incl_len, an
    unrecognised file type, or a limit breach. Individual packets that
    fail to dissect are skipped so one bad frame does not abort a
    otherwise readable capture.
    """
    limits = limits or DEFAULT_LIMITS
    path = Path(path)
    if not path.is_file():
        raise PcapParseError(f"PCAP not found: {path}")

    size = path.stat().st_size
    if size < 4:
        raise PcapParseError("PCAP is truncated (file too small)")
    if size > limits.max_file_bytes:
        raise PcapParseError(
            f"PCAP is {size:,} bytes; exceeds the "
            f"{limits.max_file_bytes:,} byte file-size limit"
        )

    with path.open("rb") as fh:
        magic = fh.read(4)
    if magic in _CLASSIC_LE or magic in _CLASSIC_BE:
        yield from _iter_classic_pcap(path, limits)
        return
    if magic == MAGIC_PCAPNG:
        yield from _iter_pcapng(path, limits)
        return
    raise PcapParseError("not a PCAP or PCAPng file (unrecognised magic)")


def load_packets(path: str | Path, limits: ParseLimits | None = None) -> list:
    """Read a bounded list of packets. Empty captures are an error."""
    packets = list(iter_packets(path, limits))
    if not packets:
        raise PcapParseError("PCAP contains no packets")
    return packets


def _iter_classic_pcap(path: Path, limits: ParseLimits) -> Iterator:
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
            raise PcapParseError("PCAP global header has snaplen 0")

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


def _iter_pcapng(path: Path, limits: ParseLimits) -> Iterator:
    """PCAPng path: file size is already capped; still bound each packet."""
    count = 0
    try:
        reader = PcapNgReader(str(path))
    except Exception as exc:
        raise PcapParseError(f"failed to open PCAPng: {exc}") from exc
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


def _dissect(cls, data: bytes):
    """Dissect one frame. Recursion is a parse error; anything else is skip."""
    try:
        return cls(data)
    except RecursionError as exc:
        raise PcapParseError("malformed packet caused parser recursion") from exc
    except Exception:
        return None
