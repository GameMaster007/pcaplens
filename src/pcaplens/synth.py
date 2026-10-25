"""Synthetic PCAP builders for demos and tests (RFC 5737 / .example only)."""
from __future__ import annotations

import base64
import random
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, IPv6, Raw, wrpcap

VICTIM = "10.10.0.21"
C2 = "203.0.113.66"
DROP = "198.51.100.23"
FS = "10.10.0.5"
SCANNER = "10.10.0.99"
# IPv6 counterparts: ULA (internal), documentation prefix (external).
VICTIM6 = "fd00:10:10::21"
C2_6 = "2001:db8:1::66"
LINKLOCAL6 = "fe80::21"
PEER_LINKLOCAL6 = "fe80::5"
LOOPBACK6 = "::1"
# RFC 5737 / RFC 2606 names for the TLS SNI fixture (issue #1).
TLS_SERVER = "198.51.100.80"
TLS_SNI_HOST = "login.example"


def ip_hdr(src: str, dst: str) -> IP | IPv6:
    """Build an IPv4 or IPv6 header. A colon in either address means IPv6."""
    if ":" in src or ":" in dst:
        return IPv6(src=src, dst=dst)
    return IP(src=src, dst=dst)


class _PcapBuilder:
    def __init__(self, seed: int = 1337) -> None:
        self.rng = random.Random(seed)
        self.base = datetime(2026, 10, 2, 8, 59, 0, tzinfo=timezone.utc).timestamp()
        self.packets: list = []
        self.macs: dict[str, str] = {}

    def mac(self, ip: str) -> str:
        if ip not in self.macs:
            self.macs[ip] = "02:00:00:{:02x}:{:02x}:{:02x}".format(*tuple(
                self.rng.randrange(256) for _ in range(3)
            ))
        return self.macs[ip]

    def add(self, pkt, t: float) -> None:
        l3 = pkt[IPv6] if IPv6 in pkt else pkt[IP]
        framed = Ether(src=self.mac(l3.src), dst=self.mac(l3.dst)) / pkt
        framed.time = self.base + t
        self.packets.append(framed)

    def dns(self, client: str, name: str, answer: str, t: float, qtype: str = "A") -> None:
        sport = self.rng.randrange(30000, 60000)
        resolver = "10.10.0.1"
        q = (
            ip_hdr(client, resolver)
            / UDP(sport=sport, dport=53)
            / DNS(id=self.rng.randrange(65535), rd=1, qd=DNSQR(qname=name, qtype=qtype))
        )
        self.add(q, t)
        rr = DNSRR(rrname=name, type=qtype, ttl=60, rdata=answer)
        r = (
            ip_hdr(resolver, client)
            / UDP(sport=53, dport=sport)
            / DNS(id=q[DNS].id, qr=1, aa=0, rd=1, ra=1, qd=q[DNS].qd, an=rr)
        )
        self.add(r, t + 0.02)

    def dns_nx(self, client: str, name: str, t: float) -> None:
        """Query plus NXDOMAIN (rcode 3) — used for burst tests."""
        sport = self.rng.randrange(30000, 60000)
        resolver = "10.10.0.1"
        q = (
            ip_hdr(client, resolver)
            / UDP(sport=sport, dport=53)
            / DNS(id=self.rng.randrange(65535), rd=1, qd=DNSQR(qname=name))
        )
        self.add(q, t)
        r = (
            ip_hdr(resolver, client)
            / UDP(sport=53, dport=sport)
            / DNS(id=q[DNS].id, qr=1, rd=1, ra=1, rcode=3, qd=q[DNS].qd)
        )
        self.add(r, t + 0.01)

    def tcp_session(
        self,
        cli: str,
        srv: str,
        dport: int,
        client_payloads: list[bytes],
        server_payloads: list[bytes],
        t: float,
        mss: int = 1400,
    ) -> float:
        sport = self.rng.randrange(40000, 65000)
        cseq = self.rng.randrange(2**31)
        sseq = self.rng.randrange(2**31)
        self.add(ip_hdr(cli, srv) / TCP(sport=sport, dport=dport, flags="S", seq=cseq), t)
        self.add(
            ip_hdr(srv, cli)
            / TCP(sport=dport, dport=sport, flags="SA", seq=sseq, ack=cseq + 1),
            t + 0.01,
        )
        cseq += 1
        sseq += 1
        self.add(
            ip_hdr(cli, srv) / TCP(sport=sport, dport=dport, flags="A", seq=cseq, ack=sseq),
            t + 0.02,
        )
        t += 0.03
        for i in range(max(len(client_payloads), len(server_payloads))):
            pairs = (
                (client_payloads[i] if i < len(client_payloads) else b"", True),
                (server_payloads[i] if i < len(server_payloads) else b"", False),
            )
            for data, src_is_client in pairs:
                for off in range(0, len(data), mss):
                    chunk = data[off : off + mss]
                    if src_is_client:
                        self.add(
                            ip_hdr(cli, srv)
                            / TCP(sport=sport, dport=dport, flags="PA", seq=cseq, ack=sseq)
                            / Raw(chunk),
                            t,
                        )
                        cseq += len(chunk)
                    else:
                        self.add(
                            ip_hdr(srv, cli)
                            / TCP(sport=dport, dport=sport, flags="PA", seq=sseq, ack=cseq)
                            / Raw(chunk),
                            t,
                        )
                        sseq += len(chunk)
                    t += 0.005
        self.add(
            ip_hdr(cli, srv) / TCP(sport=sport, dport=dport, flags="FA", seq=cseq, ack=sseq),
            t,
        )
        self.add(
            ip_hdr(srv, cli)
            / TCP(sport=dport, dport=sport, flags="FA", seq=sseq, ack=cseq + 1),
            t + 0.01,
        )
        self.add(
            ip_hdr(cli, srv)
            / TCP(sport=sport, dport=dport, flags="A", seq=cseq + 1, ack=sseq + 1),
            t + 0.02,
        )
        return t

    def http_get(
        self,
        cli: str,
        srv: str,
        host: str,
        path: str,
        body: bytes,
        ctype: str,
        t: float,
        ua: str | None = None,
    ) -> float:
        ua = ua or "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        req = (
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
            f"User-Agent: {ua}\r\nAccept: */*\r\n\r\n"
        ).encode()
        resp = (
            f"HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode() + body
        return self.tcp_session(cli, srv, 80, [req], [resp], t)

    def write(self, path: Path) -> Path:
        self.packets.sort(key=lambda p: p.time)
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        wrpcap(str(path), self.packets)
        return path


def _as_name_bytes(name: str | bytes) -> bytes:
    """On the wire SNI is ASCII; UTF-8 is kept only so invalid names can be tested."""
    if isinstance(name, bytes):
        return name
    try:
        return name.encode("ascii")
    except UnicodeEncodeError:
        return name.encode("utf-8")


def _tls_ext(ext_type: int, data: bytes) -> bytes:
    """One TLS extension: type (2) + length (2) + data."""
    return ext_type.to_bytes(2, "big") + len(data).to_bytes(2, "big") + data


def _sni_ext(names: list[bytes]) -> bytes:
    """RFC 6066 server_name list. Each entry is name_type 0 (host_name)."""
    entries = b"".join(b"\x00" + len(n).to_bytes(2, "big") + n for n in names)
    return _tls_ext(0, len(entries).to_bytes(2, "big") + entries)


def build_client_hello(
    hostname: str | bytes | None = TLS_SNI_HOST,
    extra_hostnames: list[str | bytes] | None = None,
    grease: bool = False,
) -> bytes:
    """Minimal TLS 1.2 ClientHello (not a complete handshake).

    ``hostname=None`` omits the SNI extension. Pass ``extra_hostnames`` for
    more than one SNI entry, and ``grease=True`` to wrap SNI with RFC 8701
    GREASE extensions (0x0A0A before, 0x1A1A after) so the parser skips both.
    """
    names: list[bytes] = []
    if hostname is not None:
        names.append(_as_name_bytes(hostname))
    if extra_hostnames:
        names.extend(_as_name_bytes(n) for n in extra_hostnames)

    ext_blobs: list[bytes] = []
    if grease:
        ext_blobs.append(_tls_ext(0x0A0A, b"\x00\x00"))
    if names:
        ext_blobs.append(_sni_ext(names))
    if grease:
        ext_blobs.append(_tls_ext(0x1A1A, b"\x00"))
    blob = b"".join(ext_blobs)
    extensions = len(blob).to_bytes(2, "big") + blob

    body = (
        b"\x03\x03"  # client_version TLS 1.2
        + bytes(range(32))  # random
        + b"\x00"  # empty session_id
        + b"\x00\x02\x00\x2f"  # one cipher: TLS_RSA_WITH_AES_128_CBC_SHA
        + b"\x01\x00"  # null compression
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def build_tls_sni_pcap(
    path: str | Path,
    hostname: str = TLS_SNI_HOST,
    client_hello: bytes | None = None,
    dport: int = 443,
    mss: int = 1400,
    sessions: int = 1,
) -> Path:
    """TCP flow(s) whose client payload is a TLS ClientHello.

    ``mss`` smaller than the hello splits it across TCP segments; the
    analyser joins them by sequence number. ``sessions`` > 1 emits
    reconnects to the same host so de-duplication can be tested.
    Port is not required to be 443 — TLS on 8443 is the same parse.
    """
    b = _PcapBuilder(seed=7)
    payload = client_hello if client_hello is not None else build_client_hello(hostname)
    t = 10.0
    for _ in range(sessions):
        t = b.tcp_session(VICTIM, TLS_SERVER, dport, [payload], [b""], t, mss=mss)
        t += 1.0
    return b.write(Path(path))


def build_clean_pcap(path: str | Path) -> Path:
    """Benign browsing only — should produce zero findings."""
    b = _PcapBuilder(seed=42)
    sites = [
        ("intranet.corp.example", "10.10.0.10"),
        ("news.example", "192.0.2.80"),
        ("weather.example", "192.0.2.81"),
    ]
    for i, (name, ip) in enumerate(sites):
        b.dns(VICTIM, name, ip, 5 + i * 20)
        b.http_get(
            VICTIM, ip, name, "/", b"<html><body>ordinary page</body></html>",
            "text/html", 5.1 + i * 20,
        )
        # Ordinary HTTPS: SNI must stay informational (not a finding or IOC).
        b.tcp_session(
            VICTIM, ip, 443, [build_client_hello(name)], [b""], 5.5 + i * 20,
        )
    return b.write(Path(path))


def build_attack_pcap(path: str | Path) -> Path:
    """Full lab scenario covering all six detection classes."""
    b = _PcapBuilder(seed=1337)
    sites = [
        ("intranet.corp.example", "10.10.0.10"),
        ("news.example", "192.0.2.80"),
        ("weather.example", "192.0.2.81"),
    ]
    for i, (name, ip) in enumerate(sites):
        b.dns(VICTIM, name, ip, 5 + i * 20)
        b.http_get(
            VICTIM, ip, name, "/", b"<html><body>ordinary page</body></html>",
            "text/html", 5.1 + i * 20,
        )

    b.dns(VICTIM, "update-cdn.example", DROP, 180)
    fake_pe = (
        b"MZ\x90\x00"
        + b"\x00" * 60
        + b"This program cannot be run in DOS mode.\r\n"
        + bytes(b.rng.randrange(256) for _ in range(4000))
    )
    b.http_get(
        VICTIM, DROP, "update-cdn.example", "/files/invoice_0925.exe",
        fake_pe, "application/octet-stream", 180.1,
    )

    for n in range(15):
        t = 300 + n * 60 + b.rng.uniform(-2, 2)
        req = (
            f"GET /api/v1/ping?id=WS21-{n:03d} HTTP/1.1\r\n"
            f"Host: {C2}\r\nUser-Agent: python-requests/2.31\r\n\r\n"
        ).encode()
        b.tcp_session(
            VICTIM, C2, 8080, [req],
            [b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nidle"], t,
        )

    secret = b"client_list.csv:Acme Ltd,250000;Globex,410000;Initech,95000;" * 3
    enc = base64.b32encode(secret).decode().rstrip("=").lower()
    for i in range(0, len(enc), 50):
        b.dns(
            VICTIM,
            f"{enc[i:i+50]}.{i//50}.exfil-tunnel.example",
            "203.0.113.53",
            600 + i / 25,
            qtype="A",
        )

    open_ports = {21, 22, 80, 445}
    for i, port in enumerate(b.rng.sample(range(1, 1025), 200) + sorted(open_ports)):
        t = 780 + i * 0.01
        sp = b.rng.randrange(40000, 65000)
        b.add(
            ip_hdr(SCANNER, FS)
            / TCP(sport=sp, dport=port, flags="S", seq=b.rng.randrange(2**31)),
            t,
        )
        if port in open_ports:
            b.add(ip_hdr(FS, SCANNER) / TCP(sport=port, dport=sp, flags="SA"), t + 0.001)
            b.add(ip_hdr(SCANNER, FS) / TCP(sport=sp, dport=port, flags="R"), t + 0.002)
        else:
            b.add(ip_hdr(FS, SCANNER) / TCP(sport=port, dport=sp, flags="RA"), t + 0.001)

    b.tcp_session(
        SCANNER, FS, 21,
        [b"USER backup_admin\r\n", b"PASS Summer2026!\r\n", b"LIST\r\n", b"QUIT\r\n"],
        [
            b"220 FileServer FTP ready\r\n",
            b"331 Password required\r\n",
            b"230 Login successful\r\n",
            b"150 Here comes the listing\r\n226 Done\r\n",
            b"221 Goodbye\r\n",
        ],
        900,
    )

    blob = bytes(b.rng.randrange(256) for _ in range(250_000))
    post = (
        f"POST /upload HTTP/1.1\r\nHost: {C2}:8080\r\n"
        f"User-Agent: python-requests/2.31\r\n"
        f"Content-Type: application/octet-stream\r\n"
        f"Content-Length: {len(blob)}\r\n\r\n"
    ).encode() + blob
    b.tcp_session(
        VICTIM, C2, 8080, [post],
        [b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"], 1260,
    )
    return b.write(Path(path))


def build_dual_stack_pcap(path: str | Path) -> Path:
    """IPv4 RFC 1918 plus IPv6 ULA / link-local / loopback vs documentation prefixes."""
    b = _PcapBuilder(seed=4193)
    # IPv4 internal -> RFC 5737 documentation (external); small, not exfil.
    b.http_get(
        VICTIM, DROP, "update-cdn.example", "/",
        b"<html>ok</html>", "text/html", 1.0,
    )
    # IPv6 ULA -> 2001:db8 documentation (external); large enough to trip exfil.
    blob = bytes(b.rng.randrange(256) for _ in range(250_000))
    post = (
        f"POST /upload HTTP/1.1\r\nHost: [{C2_6}]:8080\r\n"
        f"User-Agent: python-requests/2.31\r\n"
        f"Content-Type: application/octet-stream\r\n"
        f"Content-Length: {len(blob)}\r\n\r\n"
    ).encode() + blob
    b.tcp_session(
        VICTIM6, C2_6, 8080, [post],
        [b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"], 10,
    )
    # Link-local <-> link-local stays internal; must not count as exfil.
    b.tcp_session(
        LINKLOCAL6, PEER_LINKLOCAL6, 80,
        [b"GET / HTTP/1.1\r\nHost: local\r\n\r\n"],
        [b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"],
        20,
    )
    # IPv6 loopback is internal.
    b.tcp_session(LOOPBACK6, LOOPBACK6, 9, [b"hi"], [b"ok"], 30)
    return b.write(Path(path))


def build_syn_scan_pcap(path: str | Path) -> Path:
    """Half-open SYN scan: enough SYNs to trip SYN-scan, below SCAN_PORTS."""
    b = _PcapBuilder(seed=1046)
    open_ports = {22, 80}
    # 30 ports < default SCAN_PORTS (50) so only the SYN-scan rule fires.
    ports = list(range(20, 50))
    for i, port in enumerate(ports):
        t = 1.0 + i * 0.02
        sp = b.rng.randrange(40000, 65000)
        b.add(
            ip_hdr(SCANNER, FS)
            / TCP(sport=sp, dport=port, flags="S", seq=b.rng.randrange(2**31)),
            t,
        )
        if port in open_ports:
            b.add(ip_hdr(FS, SCANNER) / TCP(sport=port, dport=sp, flags="SA"), t + 0.001)
            b.add(ip_hdr(SCANNER, FS) / TCP(sport=sp, dport=port, flags="R"), t + 0.002)
        else:
            b.add(ip_hdr(FS, SCANNER) / TCP(sport=port, dport=sp, flags="RA"), t + 0.001)
    return b.write(Path(path))


def build_horizontal_scan_pcap(path: str | Path) -> Path:
    """Many hosts, one port — not a vertical port scan and below SYN_SCAN_MIN."""
    b = _PcapBuilder(seed=1047)
    for i in range(18):
        dst = f"10.10.3.{i + 1}"
        t = 1.0 + i * 0.05
        sp = b.rng.randrange(40000, 65000)
        b.add(
            ip_hdr(SCANNER, dst)
            / TCP(sport=sp, dport=22, flags="S", seq=b.rng.randrange(2**31)),
            t,
        )
        b.add(ip_hdr(dst, SCANNER) / TCP(sport=22, dport=sp, flags="RA"), t + 0.001)
    return b.write(Path(path))


def build_http_abuse_pcap(path: str | Path) -> Path:
    """Scripted UAs, a suspicious path, and a hashed non-executable download."""
    b = _PcapBuilder(seed=8080)
    # Ordinary page: must not become a finding.
    b.http_get(
        VICTIM, "192.0.2.80", "news.example", "/",
        b"<html><body>ordinary page</body></html>",
        "text/html",
        1.0,
    )
    b.http_get(
        VICTIM, DROP, "files.example", "/admin/settings",
        b"<html>panel</html>",
        "text/html",
        5.0,
        ua="curl/8.6.0",
    )
    zip_body = b"PK\x03\x04" + bytes(b.rng.randrange(256) for _ in range(80))
    b.http_get(
        VICTIM, DROP, "files.example", "/export/dump.zip",
        zip_body,
        "application/zip",
        8.0,
        ua="wget/1.21",
    )
    return b.write(Path(path))


def build_dns_abuse_pcap(path: str | Path) -> Path:
    """NXDOMAIN burst, DGA-like names, an odd long label, many subdomains."""
    b = _PcapBuilder(seed=5353)
    for i in range(20):
        b.dns_nx(VICTIM, f"gone{i}.missing.example", 2.0 + i * 0.2)
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    for i in range(16):
        label = "".join(alphabet[(i * 7 + n) % len(alphabet)] for n in range(14))
        b.dns(VICTIM, f"{label}.dga-lab.example", "203.0.113.9", 20 + i * 0.3)
    b.dns(VICTIM, f"{'q' * 30}.odd-label.example", "192.0.2.9", 40)
    for i in range(10):
        b.dns(VICTIM, f"{'a' * 22}{i}.tunnel-sign.example", "203.0.113.10", 50 + i)
    return b.write(Path(path))
