"""Builders for tiny malformed PCAPs used by the robustness tests.

None of these files are committed as binaries. The huge-capture helper
writes a real-sized file at test time so the repo stays small.
"""
from __future__ import annotations

import struct
from pathlib import Path

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import CookedLinux, CookedLinuxV2, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap, wrpcapng

# Classic libpcap magics as integers (struct.pack chooses the on-disk order).
_MAGIC_USEC = 0xA1B2C3D4
_MAGIC_NSEC = 0xA1B23C4D
_ETHERNET = 1


def pcap_global_header(
    *,
    snaplen: int = 65535,
    network: int = _ETHERNET,
    endian: str = "<",
    nsec: bool = False,
) -> bytes:
    """24-byte classic PCAP file header.

    `endian` is '<' (little, the tcpdump/scapy default) or '>' (big).
    `nsec` selects the nanosecond-resolution magic.
    """
    magic = _MAGIC_NSEC if nsec else _MAGIC_USEC
    return struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, snaplen, network)


def pcap_record(
    data: bytes,
    *,
    incl_len: int | None = None,
    orig_len: int | None = None,
    endian: str = "<",
) -> bytes:
    """16-byte packet header plus the bytes that actually follow it.

    `incl_len` may lie (bogus / truncated cases). Callers decide how many
    payload bytes to append.
    """
    if incl_len is None:
        incl_len = len(data)
    if orig_len is None:
        orig_len = incl_len
    return struct.pack(endian + "IIII", 0, 0, incl_len, orig_len) + data


def tiny_packet():
    """One Ethernet/IP/UDP packet (scapy object) used by several writers."""
    return (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="10.10.0.21", dst="10.10.0.1")
        / UDP(sport=12345, dport=53)
        / Raw(b"x")
    )


def tiny_frame() -> bytes:
    """On-wire bytes of `tiny_packet()`."""
    return bytes(tiny_packet())


def write_bytes(path: Path, blob: bytes) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(blob)
    return path


def write_empty_file(path: Path) -> Path:
    """Zero-byte file — no magic, no header."""
    return write_bytes(path, b"")


def write_truncated_header(path: Path) -> Path:
    """File shorter than the 24-byte global header."""
    return write_bytes(path, pcap_global_header()[:10])


def write_incomplete_packet_header(path: Path) -> Path:
    """Valid global header, then only 8 of the 16 packet-header bytes."""
    return write_bytes(path, pcap_global_header() + b"\x00" * 8)


def write_zero_length_packet(path: Path) -> Path:
    """A record that claims to capture 0 bytes (nothing to dissect)."""
    return write_bytes(path, pcap_global_header() + pcap_record(b"", incl_len=0, orig_len=0))


def write_truncated_packet(path: Path) -> Path:
    """Packet header claims 200 captured bytes; only 8 follow."""
    header = pcap_global_header()
    record = pcap_record(b"\x00" * 8, incl_len=200, orig_len=200)
    return write_bytes(path, header + record)


def write_bogus_incl_len(path: Path) -> Path:
    """incl_len is ~2 GiB. A naive reader would hang or allocate hugely.

    Only a few bytes of payload are present so the file stays tiny.
    """
    header = pcap_global_header()
    record = pcap_record(b"\x00\x01\x02\x03", incl_len=0x7FFFFFFF, orig_len=0x7FFFFFFF)
    return write_bytes(path, header + record)


def write_bogus_snaplen(path: Path) -> Path:
    """Global snaplen is 0 (illegal) plus one empty-looking record."""
    header = pcap_global_header(snaplen=0)
    record = pcap_record(b"\x00" * 14, incl_len=14, orig_len=14)
    return write_bytes(path, header + record)


def write_empty_pcap(path: Path) -> Path:
    """Valid global header, zero packets."""
    return write_bytes(path, pcap_global_header())


def write_garbage(path: Path) -> Path:
    """Random-looking bytes that are not a PCAP at all."""
    return write_bytes(path, b"this is not a pcap file\x00\x01\x02")


def write_malformed_dns(path: Path) -> Path:
    """Ethernet/IP/UDP frames whose DNS payload is illegal.

    Cases: oversize label length, a compression pointer loop, and a
    truncated question section. The surrounding L2/L3 headers are valid
    so a robust analyser should skip the DNS decode rather than crash.
    """
    # Label length 0xFF but only a handful of bytes follow.
    oversize_label = (
        struct.pack("!HHHHHH", 0x1111, 0x0100, 1, 0, 0, 0) + b"\xffABCDEFGH"
    )
    # Pointer at the start of the qname pointing at itself (offset 12).
    pointer_loop = (
        struct.pack("!HHHHHH", 0x2222, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c\x00\x01\x00\x01"
    )
    # qdcount=1 but the name is cut off after one length byte.
    truncated_question = struct.pack("!HHHHHH", 0x3333, 0x0100, 1, 0, 0, 0) + b"\x03ab"

    packets = []
    for i, payload in enumerate((oversize_label, pointer_loop, truncated_question)):
        packets.append(
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src="10.10.0.21", dst="10.10.0.1")
            / UDP(sport=40000 + i, dport=53)
            / Raw(payload)
        )
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(path), packets)
    return path


def write_malformed_http(path: Path) -> Path:
    """TCP streams with HTTP that a naive parser would choke on.

    - Content-Length is not an integer
    - Content-Length is a huge positive integer (body is tiny)
    - Request line is only "GET " (no URI)
    """
    bad_length = b"GET / HTTP/1.1\r\nHost: a.example\r\nContent-Length: not-a-number\r\n\r\nxx"
    huge_length = (
        b"GET /huge HTTP/1.1\r\nHost: a.example\r\n"
        b"Content-Length: 999999999\r\n\r\nshort"
    )
    no_uri = b"GET \r\nHost: a.example\r\n\r\n"
    packets = []
    for i, body in enumerate((bad_length, huge_length, no_uri)):
        packets.append(
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src="10.10.0.21", dst="198.51.100.10")
            / TCP(sport=41000 + i, dport=80, flags="PA", seq=1)
            / Raw(body)
        )
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(path), packets)
    return path


def write_valid_tiny_pcap(path: Path, *, endian: str = "<", nsec: bool = False) -> Path:
    """One valid Ethernet/IP/UDP frame in the requested byte order."""
    frame = tiny_frame()
    blob = pcap_global_header(endian=endian, nsec=nsec) + pcap_record(
        frame, endian=endian
    )
    return write_bytes(path, blob)


def write_pcapng(path: Path) -> Path:
    """One valid frame in PCAPng (built at test time, not committed)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    wrpcapng(str(path), [tiny_packet()])
    return path


def write_truncated_pcapng(path: Path) -> Path:
    """PCAPng magic plus two leftover bytes — not a complete SHB."""
    return write_bytes(path, b"\x0a\x0d\x0d\x0a\x00\x00")


def write_pcapng_lying_block_length(path: Path, size: int = 120) -> Path:
    """~120-byte PCAPng whose next block claims ~2.1 GiB.

    A naive reader would honour Total Length and try to allocate that
    many bytes. The file stays tiny so the remaining-bytes check must fire.
    """
    # Minimal little-endian SHB (28 bytes), then type+tot_len with tot_len=2^31-1.
    shb = struct.pack("<IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
    # 0x7FFFFFFC ≈ 2.1 GiB and is 4-byte aligned (unaligned lengths are
    # rejected earlier; this hits the remaining-bytes check).
    lie = struct.pack("<II", 6, 0x7FFFFFFC)
    blob = shb + lie + b"\x00" * max(0, size - len(shb) - len(lie))
    return write_bytes(path, blob[:size])


def write_snaplen_truncated_pcap(path: Path, orig_len: int = 9000) -> Path:
    """Captured length is small; on-wire orig_len is a jumbo frame."""
    frame = tiny_frame()
    blob = pcap_global_header() + pcap_record(frame, incl_len=len(frame), orig_len=orig_len)
    return write_bytes(path, blob)


def write_pcapng_snaplen_truncated(path: Path, orig_len: int = 9000) -> Path:
    """PCAPng EPB with a small captured length and a huge original length."""
    frame = tiny_frame()
    caplen = len(frame)
    pad = (4 - (caplen % 4)) % 4
    shb = struct.pack("<IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
    idb = struct.pack("<IIHHI I", 1, 20, 1, 0, 65535, 20)
    epb_len = 32 + caplen + pad
    epb = struct.pack("<IIIIIII", 6, epb_len, 0, 0, 0, caplen, orig_len)
    epb += frame + (b"\x00" * pad) + struct.pack("<I", epb_len)
    return write_bytes(path, shb + idb + epb)


def write_sll_pcap(path: Path, *, version: int = 1, ipv6: bool = False) -> Path:
    """Linux cooked capture (tcpdump -i any): SLL or SLL2."""
    if ipv6:
        l3 = IPv6(src="fd00:10:10::21", dst="2001:db8::1") / UDP(sport=12345, dport=53) / Raw(
            b"sll-v6"
        )
        proto = 0x86DD
    else:
        l3 = IP(src="10.10.0.21", dst="10.10.0.1") / UDP(sport=12345, dport=53) / Raw(b"sll-v4")
        proto = 0x0800
    if version == 2:
        pkt = CookedLinuxV2(proto=proto) / l3
        network = 276
    else:
        pkt = CookedLinux(proto=proto) / l3
        network = 113
    return write_bytes(path, pcap_global_header(network=network) + pcap_record(bytes(pkt)))


def write_raw_ipv6_pcap(path: Path) -> Path:
    """DLT_RAW (101) IPv6 datagram, no Ethernet header."""
    frame = bytes(
        IPv6(src="fd00::1", dst="2001:db8::1") / UDP(sport=1234, dport=53) / Raw(b"raw6")
    )
    return write_bytes(path, pcap_global_header(network=101) + pcap_record(frame))


def write_huge_pcap(path: Path, min_bytes: int = 1_048_576) -> Path:
    """Write a valid PCAP that is at least `min_bytes` on disk.

    Built at test time from repeated tiny Ethernet frames so we never
    commit a large binary. Writing in chunks keeps this fast in CI.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    header = pcap_global_header()
    # 60 zero bytes is a legal (if dull) Ethernet frame.
    record = pcap_record(bytes(60))
    # Repeat the record so a single write() covers a lot of ground.
    chunk = record * 256
    with path.open("wb") as fh:
        fh.write(header)
        written = len(header)
        while written < min_bytes:
            fh.write(chunk)
            written += len(chunk)
    return path


def write_many_tiny_packets(path: Path, count: int) -> Path:
    """Valid PCAP with `count` tiny frames (for the packet-count limit)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    record = pcap_record(bytes(60))
    with path.open("wb") as fh:
        fh.write(pcap_global_header())
        # Avoid a Python loop of write() per packet when count is large.
        chunk = record * 256
        remaining = count
        while remaining >= 256:
            fh.write(chunk)
            remaining -= 256
        if remaining:
            fh.write(record * remaining)
    return path


def small_corpus(dir_path: Path) -> dict[str, Path]:
    """Write every small malformed fixture into `dir_path` and return paths."""
    dir_path = Path(dir_path)
    dir_path.mkdir(parents=True, exist_ok=True)
    return {
        "truncated_header": write_truncated_header(dir_path / "truncated_header.pcap"),
        "truncated_packet": write_truncated_packet(dir_path / "truncated_packet.pcap"),
        "incomplete_packet_header": write_incomplete_packet_header(
            dir_path / "incomplete_phdr.pcap"
        ),
        "bogus_incl_len": write_bogus_incl_len(dir_path / "bogus_incl_len.pcap"),
        "bogus_snaplen": write_bogus_snaplen(dir_path / "bogus_snaplen.pcap"),
        "empty": write_empty_pcap(dir_path / "empty.pcap"),
        "empty_file": write_empty_file(dir_path / "empty_file.pcap"),
        "zero_length_packet": write_zero_length_packet(dir_path / "zero_len.pcap"),
        "garbage": write_garbage(dir_path / "garbage.pcap"),
        "truncated_pcapng": write_truncated_pcapng(dir_path / "trunc.pcapng"),
        "pcapng_lying_block": write_pcapng_lying_block_length(dir_path / "lie.pcapng"),
        "malformed_dns": write_malformed_dns(dir_path / "malformed_dns.pcap"),
        "malformed_http": write_malformed_http(dir_path / "malformed_http.pcap"),
    }
