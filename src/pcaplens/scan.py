"""Port-scan and SYN-scan (half-open) detections."""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from scapy.all import IP, TCP, IPv6

from pcaplens.thresholds import Thresholds

# Cut-offs kept here so YAML profiles stay backward-compatible.
# Horizontal scan must not fire on ordinary HTTPS browsing (many hosts,
# ports {80,443}). Require a non-web port set *or* a half-open ratio.
SYN_SCAN_MIN = 20
SYN_SCAN_COMPLETE_RATIO = 0.20
HORIZONTAL_HOSTS = 15
HORIZONTAL_MAX_PORTS = 3
_WEB_PORTS = frozenset({80, 443, 8080, 8443})


def _l3_addrs(pkt: Any) -> tuple[str, str] | None:
    if IP in pkt:
        return pkt[IP].src, pkt[IP].dst
    if IPv6 in pkt:
        return pkt[IPv6].src, pkt[IPv6].dst
    return None


def _tcp_flag_str(pkt: Any) -> str:
    try:
        return str(pkt[TCP].flags)
    except Exception:
        return ""


def analyze_scans(
    pkts: Any,
    thr: Thresholds | None = None,
) -> tuple[list[tuple[str, str, str]], list[tuple], list[tuple[str, str, str]]]:
    """Return (findings, events, iocs) for scan heuristics.

    Vertical port-scan (many dports, one target) uses Thresholds.SCAN_*.
    SYN-scan looks for many SYN-only probes with few completed handshakes
    (scanner RST after SYN-ACK, or no client ACK). Horizontal scan is many
    destinations and few ports.
    """
    thr = thr if thr is not None else Thresholds()
    findings: list[tuple[str, str, str]] = []
    events: list[tuple] = []
    iocs: list[tuple[str, str, str]] = []
    seen_ioc: set[tuple[str, str]] = set()

    def add_ioc(kind: str, value: str, context: str) -> None:
        if (kind, value) in seen_ioc:
            return
        seen_ioc.add((kind, value))
        iocs.append((kind, value, context))

    syns: dict[tuple[str, str], list[tuple[float, int]]] = defaultdict(list)
    syn_count: dict[str, int] = defaultdict(int)
    client_ack: dict[str, int] = defaultdict(int)
    client_rst: dict[str, int] = defaultdict(int)
    dests_by_src: dict[str, set[str]] = defaultdict(set)
    ports_by_src: dict[str, set[int]] = defaultdict(set)
    first_syn: dict[str, float] = {}

    for p in pkts:
        try:
            addrs = _l3_addrs(p)
            if not addrs or TCP not in p:
                continue
            src, dst = addrs
            flags = _tcp_flag_str(p)
            t = float(p.time)
            dport = int(p[TCP].dport)
        except Exception:
            continue
        if flags == "S":
            syns[(src, dst)].append((t, dport))
            syn_count[src] += 1
            dests_by_src[src].add(dst)
            ports_by_src[src].add(dport)
            first_syn.setdefault(src, t)
        elif "S" not in flags and "A" in flags:
            # Client ACK (or PSH+ACK) after the handshake — a completed connect.
            client_ack[src] += 1
        if "R" in flags and "S" not in flags:
            client_rst[src] += 1

    for (src, dst), lst in syns.items():
        lst.sort()
        for i in range(len(lst)):
            window = {
                port
                for t, port in lst
                if lst[i][0] <= t <= lst[i][0] + thr.SCAN_WINDOW
            }
            if len(window) >= thr.SCAN_PORTS:
                open_ports = sorted(
                    {
                        p[TCP].sport
                        for p in pkts
                        if TCP in p
                        and _tcp_flag_str(p) == "SA"
                        and _l3_addrs(p) == (dst, src)
                    }
                )
                desc = (
                    f"{src} probed {len(window)} ports on {dst} "
                    f"in <= {thr.SCAN_WINDOW}s (open: {open_ports})"
                )
                events.append(
                    (
                        lst[i][0],
                        "HIGH",
                        "Port scan",
                        desc,
                        "T1046 Network Service Discovery",
                    )
                )
                findings.append(("HIGH", "Port scan", desc))
                add_ioc("ip", src, "internal scanning host")
                break

    for src, n_syn in syn_count.items():
        if n_syn < SYN_SCAN_MIN:
            continue
        acks = client_ack[src]
        ratio = acks / n_syn if n_syn else 1.0
        if ratio > SYN_SCAN_COMPLETE_RATIO and client_rst[src] == 0:
            continue
        desc = (
            f"{src} sent {n_syn} SYN probes with {acks} completed handshakes "
            f"({ratio:.0%}) and {client_rst[src]} RST replies "
            f"(half-open / SYN scan)"
        )
        t0 = first_syn.get(src, 0.0)
        events.append(
            (t0, "HIGH", "SYN scan", desc, "T1046 Network Service Discovery")
        )
        findings.append(("HIGH", "SYN scan (half-open)", desc))
        add_ioc("ip", src, "SYN-scan source")

    for src, dests in dests_by_src.items():
        ports = ports_by_src[src]
        if len(dests) < HORIZONTAL_HOSTS or len(ports) > HORIZONTAL_MAX_PORTS:
            continue
        n_syn = syn_count[src]
        complete_ratio = (client_ack[src] / n_syn) if n_syn else 1.0
        web_only = bool(ports) and ports <= _WEB_PORTS
        if web_only and complete_ratio > SYN_SCAN_COMPLETE_RATIO:
            continue
        desc = (
            f"{src} probed {len(dests)} hosts on {len(ports)} port(s) "
            f"{sorted(ports)[:8]} (horizontal scan)"
        )
        t0 = first_syn.get(src, 0.0)
        events.append(
            (
                t0,
                "HIGH",
                "Horizontal scan",
                desc,
                "T1046 Network Service Discovery",
            )
        )
        findings.append(("HIGH", "Horizontal port scan", desc))
        add_ioc("ip", src, "horizontal scanning host")

    return findings, events, iocs
