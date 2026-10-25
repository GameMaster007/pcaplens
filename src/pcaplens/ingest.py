"""Single-pass ingest: stream packets, keep compact facts, drop Scapy objects."""
from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scapy.all import DNS, IP, TCP, UDP, IPv6

from pcaplens.parse import DEFAULT_LIMITS, ParseLimits, PcapParseError, iter_packets


@dataclass(frozen=True)
class TcpEvent:
    t: float
    src: str
    dst: str
    sport: int
    dport: int
    flags: str
    seq: int
    payload: bytes
    nbytes: int


@dataclass(frozen=True)
class DnsFact:
    t: float
    src: str
    dst: str
    qr: int
    rcode: int
    qname: str | None
    sport: int
    dport: int


@dataclass
class CaptureView:
    """Everything analyze_pcap needs after a single streaming pass."""

    packet_count: int
    t0: float
    t1: float
    talk: Counter
    tcp: list[TcpEvent] = field(default_factory=list)
    dns: list[DnsFact] = field(default_factory=list)
    streams: dict = field(default_factory=dict)
    first_seen: dict = field(default_factory=dict)


def _l3_addrs(pkt: Any) -> tuple[str, str] | None:
    if IP in pkt:
        return pkt[IP].src, pkt[IP].dst
    if IPv6 in pkt:
        return pkt[IPv6].src, pkt[IPv6].dst
    return None


def _qname(pkt: Any, max_bytes: int) -> str | None:
    try:
        if DNS not in pkt or not pkt.haslayer("DNSQR"):
            return None
        raw = pkt["DNSQR"].qname
        if raw is None:
            return None
        if isinstance(raw, bytes):
            if len(raw) > max_bytes:
                return None
            name = raw.decode("ascii", errors="replace")
        else:
            name = str(raw)
            if len(name) > max_bytes:
                return None
        return name.rstrip(".")
    except Exception:
        return None


def reassemble_events(
    events: Iterable[TcpEvent],
    max_stream_bytes: int = DEFAULT_LIMITS.max_stream_bytes,
) -> tuple[dict, dict]:
    streams: dict = defaultdict(dict)
    first_seen: dict = {}
    sizes: dict = defaultdict(int)
    for e in events:
        if not e.payload:
            continue
        key = (e.src, e.sport, e.dst, e.dport)
        first_seen.setdefault(key, e.t)
        if e.seq in streams[key]:
            continue
        if sizes[key] + len(e.payload) > max_stream_bytes:
            continue
        streams[key][e.seq] = e.payload
        sizes[key] += len(e.payload)
    return (
        {k: b"".join(v[s] for s in sorted(v)) for k, v in streams.items()},
        first_seen,
    )


def ingest_capture(
    path: str | Path,
    limits: ParseLimits | None = None,
) -> CaptureView:
    """Stream `path` once. Peak extra memory is compact facts, not the file."""
    limits = limits or DEFAULT_LIMITS
    talk: Counter = Counter()
    tcp: list[TcpEvent] = []
    dns: list[DnsFact] = []
    count = 0
    t0 = t1 = 0.0
    for pkt in iter_packets(path, limits):
        count += 1
        try:
            t = float(pkt.time)
        except (TypeError, ValueError, AttributeError):
            t = 0.0
        if count == 1:
            t0 = t1 = t
        else:
            if t < t0:
                t0 = t
            if t > t1:
                t1 = t
        try:
            addrs = _l3_addrs(pkt)
            nbytes = len(pkt)
        except Exception:
            continue
        if addrs:
            talk[addrs] += nbytes
            src, dst = addrs
            try:
                if TCP in pkt:
                    payload = bytes(pkt[TCP].payload)
                    tcp.append(
                        TcpEvent(
                            t=t,
                            src=src,
                            dst=dst,
                            sport=int(pkt[TCP].sport),
                            dport=int(pkt[TCP].dport),
                            flags=str(pkt[TCP].flags),
                            seq=int(pkt[TCP].seq),
                            payload=payload,
                            nbytes=nbytes,
                        )
                    )
            except Exception:
                pass
            try:
                if DNS in pkt:
                    sport = int(pkt[UDP].sport) if UDP in pkt else 0
                    dport = int(pkt[UDP].dport) if UDP in pkt else 0
                    qr = int(pkt[DNS].qr)
                    rcode = int(pkt[DNS].rcode)
                    dns.append(
                        DnsFact(
                            t=t,
                            src=src,
                            dst=dst,
                            qr=qr,
                            rcode=rcode,
                            qname=_qname(pkt, limits.max_dns_name_bytes),
                            sport=sport,
                            dport=dport,
                        )
                    )
            except Exception:
                pass
        del pkt
    if count == 0:
        raise PcapParseError("PCAP contains no packets")
    streams, first_seen = reassemble_events(tcp, limits.max_stream_bytes)
    return CaptureView(
        packet_count=count,
        t0=t0,
        t1=t1,
        talk=talk,
        tcp=tcp,
        dns=dns,
        streams=streams,
        first_seen=first_seen,
    )
