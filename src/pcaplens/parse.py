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

from scapy.all import IP, Ether, IPv6
from scapy.config import conf as scapy_conf
from scapy.layers.dns import DNS
from scapy.layers.l2 import CookedLinux, CookedLinuxV2

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
# DLT_LINUX_SLL / SLL2 = tcpdump -i any (Linux cooked capture).
DLT_EN10MB = 1
DLT_RAW = 101
DLT_LINUX_SLL = 113
DLT_LINUX_SLL2 = 276

# PCAPng block types (RFC 6282 / pcapng spec).
_PCAPNG_SHB = 0x0A0D0D0A
_PCAPNG_IDB = 1
_PCAPNG_PB = 2  # obsolete Packet Block
_PCAPNG_SPB = 3
_PCAPNG_EPB = 6
_PCAPNG_BOM_LE = 0x1A2B3C4D
_PCAPNG_BOM_BE = 0x4D3C2B1A
_PCAPNG_MIN_BLOCK = 12


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
        yield from _iter_pcapng(path, limits, size)
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

        count = 0
        while True:
            phdr = fh.read(16)
            if not phdr:
                break
            if len(phdr) < 16:
                raise PcapParseError("PCAP is truncated (incomplete packet header)")
            ts_sec, ts_sub, incl_len, _orig_len = struct.unpack(endian + "IIII", phdr)
            # Bound the *captured* length (incl_len), never orig_len / wirelen.
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
            pkt = _dissect_link(network, data)
            if pkt is None:
                continue
            denom = 1_000_000_000.0 if nsec else 1_000_000.0
            pkt.time = float(ts_sec) + float(ts_sub) / denom
            yield pkt


def _iter_pcapng(path: Path, limits: ParseLimits, size: int) -> Iterator[Any]:
    """Walk PCAPng blocks, checking every Total Length against remaining bytes.

    Scapy's PcapNgReader would honour a lying block length and try to
    allocate gigabytes from a 120-byte file. We never read() more than
    the bytes still on disk.
    """
    with path.open("rb") as fh:
        endian, interfaces = _read_pcapng_shb(fh, size)
        count = 0
        while True:
            pos = fh.tell()
            remaining = size - pos
            if remaining == 0:
                break
            prefix = fh.read(8)
            if not prefix:
                break
            if len(prefix) < 8:
                raise PcapParseError("PCAPng is truncated (incomplete block header)")
            block_type, tot_len = struct.unpack(endian + "II", prefix)
            _check_pcapng_block_len(tot_len, remaining, "block")
            rest = fh.read(tot_len - 8)
            if len(rest) < tot_len - 8:
                raise PcapParseError(
                    f"PCAPng is truncated (block promised {tot_len} bytes, "
                    f"{8 + len(rest)} available)"
                )
            body = rest[:-4]
            if block_type == _PCAPNG_SHB:
                endian, interfaces = _parse_pcapng_shb_body(prefix + rest, remaining)
                continue
            if block_type == _PCAPNG_IDB:
                _parse_pcapng_idb(body, endian, interfaces)
                continue
            caplen, orig_len, ts, if_id = _pcapng_packet_fields(
                block_type, body, tot_len, endian
            )
            if caplen is None:
                continue
            # Packet-size cap is the *captured* length, not on-wire orig_len.
            if caplen > limits.max_packet_bytes:
                raise PcapParseError(
                    f"packet {count + 1} captured length is {caplen:,} bytes; "
                    f"exceeds the {limits.max_packet_bytes:,} byte packet-size limit"
                )
            data = _pcapng_packet_bytes(block_type, body, tot_len, endian)
            if data is None:
                continue
            count += 1
            if count > limits.max_packets:
                raise PcapParseError(
                    f"PCAP exceeds the {limits.max_packets:,} packet count limit"
                )
            if not data:
                continue
            pkt = _dissect_link(_pcapng_linktype(interfaces, if_id), data)
            if pkt is None:
                continue
            pkt.time = ts
            pkt.wirelen = orig_len
            yield pkt


def _read_pcapng_shb(
    fh: Any, size: int
) -> tuple[str, dict[int, tuple[int, int]]]:
    """Read the opening Section Header Block and return (endian, interfaces)."""
    prefix = fh.read(12)
    if len(prefix) < 12:
        raise PcapParseError("PCAPng is truncated (incomplete section header)")
    block_type = struct.unpack("<I", prefix[:4])[0]
    if block_type != _PCAPNG_SHB:
        raise PcapParseError("PCAPng missing section header block")
    bom = struct.unpack("<I", prefix[8:12])[0]
    if bom == _PCAPNG_BOM_LE:
        endian = "<"
    elif bom == _PCAPNG_BOM_BE:
        endian = ">"
    else:
        # Big-endian files store BOM as 1A2B3C4D in file order too once swapped.
        bom_be = struct.unpack(">I", prefix[8:12])[0]
        if bom_be == _PCAPNG_BOM_LE:
            endian = ">"
        else:
            raise PcapParseError("PCAPng has invalid byte-order magic")
    tot_len = struct.unpack(endian + "I", prefix[4:8])[0]
    remaining = size - (fh.tell() - 12)
    _check_pcapng_block_len(tot_len, remaining, "section header")
    rest = fh.read(tot_len - 12)
    if len(rest) < tot_len - 12:
        raise PcapParseError("PCAPng is truncated (incomplete section header)")
    return endian, {}


def _parse_pcapng_shb_body(
    block: bytes, remaining: int
) -> tuple[str, dict[int, tuple[int, int]]]:
    """Re-enter a later SHB (new section). `block` is the full block bytes."""
    if len(block) < 16:
        raise PcapParseError("PCAPng is truncated (incomplete section header)")
    bom = struct.unpack("<I", block[8:12])[0]
    if bom == _PCAPNG_BOM_LE:
        endian = "<"
    elif bom == _PCAPNG_BOM_BE:
        endian = ">"
    else:
        bom_be = struct.unpack(">I", block[8:12])[0]
        if bom_be == _PCAPNG_BOM_LE:
            endian = ">"
        else:
            raise PcapParseError("PCAPng has invalid byte-order magic")
    tot_len = struct.unpack(endian + "I", block[4:8])[0]
    _check_pcapng_block_len(tot_len, remaining, "section header")
    return endian, {}


def _check_pcapng_block_len(tot_len: int, remaining: int, label: str) -> None:
    """Reject a block whose Total Length would read or allocate past the file."""
    if tot_len < _PCAPNG_MIN_BLOCK:
        raise PcapParseError(
            f"PCAPng {label} length {tot_len} is below the {_PCAPNG_MIN_BLOCK}-byte minimum"
        )
    if tot_len % 4 != 0:
        raise PcapParseError(f"PCAPng {label} length {tot_len} is not 4-byte aligned")
    if tot_len > remaining:
        raise PcapParseError(
            f"PCAPng {label} claims {tot_len:,} bytes; only {remaining} remain in the file"
        )


def _parse_pcapng_idb(body: bytes, endian: str, interfaces: dict[int, tuple[int, int]]) -> None:
    if len(body) < 8:
        raise PcapParseError("PCAPng interface description is truncated")
    linktype, _reserved, snaplen = struct.unpack(endian + "HHI", body[:8])
    interfaces[len(interfaces)] = (linktype, snaplen)


def _pcapng_linktype(interfaces: dict[int, tuple[int, int]], if_id: int | None) -> int:
    if if_id is not None and if_id in interfaces:
        return interfaces[if_id][0]
    if interfaces:
        return next(iter(interfaces.values()))[0]
    return DLT_EN10MB


def _pcapng_packet_fields(
    block_type: int, body: bytes, tot_len: int, endian: str
) -> tuple[int | None, int, float, int | None]:
    """Return (captured_len, orig_len, timestamp, if_id) or captured_len None."""
    if block_type == _PCAPNG_EPB:
        if len(body) < 20:
            return None, 0, 0.0, None
        if_id, ts_hi, ts_lo, caplen, origlen = struct.unpack(endian + "IIIII", body[:20])
        ts = ((ts_hi << 32) | ts_lo) / 1_000_000.0
        return caplen, origlen, ts, if_id
    if block_type == _PCAPNG_SPB:
        if len(body) < 4:
            return None, 0, 0.0, None
        (origlen,) = struct.unpack(endian + "I", body[:4])
        # Packet bytes sit between origlen and the trailing total-length field.
        caplen = min(origlen, max(tot_len - 16, 0))
        return caplen, origlen, 0.0, 0
    if block_type == _PCAPNG_PB:
        if len(body) < 20:
            return None, 0, 0.0, None
        if_id16, _drops, ts_hi, ts_lo, caplen, origlen = struct.unpack(
            endian + "HHIIII", body[:20]
        )
        ts = ((ts_hi << 32) | ts_lo) / 1_000_000.0
        return caplen, origlen, ts, if_id16
    return None, 0, 0.0, None


def _pcapng_packet_bytes(
    block_type: int, body: bytes, tot_len: int, endian: str
) -> bytes | None:
    caplen, _orig, _ts, _if_id = _pcapng_packet_fields(block_type, body, tot_len, endian)
    if caplen is None:
        return None
    if block_type == _PCAPNG_EPB:
        data = body[20 : 20 + caplen]
    elif block_type == _PCAPNG_SPB:
        data = body[4 : 4 + caplen]
    else:
        data = body[20 : 20 + caplen]
    if len(data) < caplen:
        raise PcapParseError(
            f"PCAPng packet promised {caplen} captured bytes, got {len(data)}"
        )
    return data


def _dissect_link(network: int, data: bytes) -> Any:
    """Dissect one frame using the capture's link type."""
    if network == DLT_RAW:
        return _dissect_raw(data)
    if network == DLT_LINUX_SLL:
        return _dissect(CookedLinux, data)
    if network == DLT_LINUX_SLL2:
        return _dissect(CookedLinuxV2, data)
    return _dissect(Ether, data)


def _dissect_raw(data: bytes) -> Any:
    """DLT_RAW is a bare IPv4 or IPv6 datagram (version nibble)."""
    if not data:
        return None
    version = data[0] >> 4
    if version == 6:
        return _dissect(IPv6, data)
    return _dissect(IP, data)


def _dissect(cls: type, data: bytes) -> Any:
    """Dissect one frame. Recursion is a parse error; anything else is skip."""
    try:
        return cls(data)
    except RecursionError as exc:
        raise PcapParseError("malformed packet caused parser recursion") from exc
    except Exception:
        return None
