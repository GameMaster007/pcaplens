"""DNS triage: long/odd names, NXDOMAIN bursts, DGA, tunnelling signs."""
from __future__ import annotations

from collections import Counter, defaultdict
from math import log2
from typing import Any

from scapy.all import DNS, IP, UDP, IPv6

from pcaplens.ingest import DnsFact

# Cut-offs kept here so YAML profiles stay backward-compatible.
# Tuned against benign CDN / Windows-Update / browsing captures:
# 20 unique labels (CDNs rarely mint that many *new* high-entropy names
# in one short capture); length 12 / 3.5 bits matches the YAML DNS_* pair.
NXDOMAIN_COUNT = 15
NXDOMAIN_WINDOW = 10.0
DGA_UNIQUE = 20
DGA_LABEL_LEN = 12
DGA_ENTROPY = 3.5
ODD_LABEL_LEN = 25
TUNNEL_UNIQUE = 16


def _entropy(s: str) -> float:
    counts = Counter(s)
    return (
        -sum(n / len(s) * log2(n / len(s)) for n in counts.values()) if s else 0.0
    )


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


def _client(pkt: Any) -> str | None:
    addrs = _l3_addrs(pkt)
    if not addrs:
        return None
    src, dst = addrs
    if UDP in pkt and pkt[UDP].dport == 53:
        return src
    if UDP in pkt and pkt[UDP].sport == 53:
        return dst
    return src


def analyze_dns(
    pkts: Any,
    *,
    max_name_bytes: int = 255,
) -> tuple[list[tuple[str, str, str]], list[tuple], list[tuple[str, str, str]]]:
    """Return (findings, events, iocs) for DNS heuristics.

    Existing long-label tunnelling in analyze_pcap still runs; this module
    adds NXDOMAIN bursts, a simple DGA score, odd labels, and a
    many-subdomain tunnelling sign.
    """
    findings: list[tuple[str, str, str]] = []
    events: list[tuple] = []
    iocs: list[tuple[str, str, str]] = []
    seen_ioc: set[tuple[str, str]] = set()

    def add_ioc(kind: str, value: str, context: str) -> None:
        if (kind, value) in seen_ioc:
            return
        seen_ioc.add((kind, value))
        iocs.append((kind, value, context))

    nx_by_client: dict[str, list[float]] = defaultdict(list)
    queries_by_base: dict[str, set[str]] = defaultdict(set)
    dga_names: list[tuple[float, str]] = []
    odd: list[tuple[float, str]] = []

    for p in pkts:
        try:
            if isinstance(p, DnsFact):
                name = p.qname
                t = p.t
                qr, rcode = p.qr, p.rcode
                client = p.dst if p.sport == 53 else p.src
            else:
                if DNS not in p:
                    continue
                name = _qname(p, max_name_bytes)
                t = float(p.time)
                qr = int(p[DNS].qr)
                rcode = int(p[DNS].rcode)
                client = _client(p) or "?"
        except Exception:
            continue
        if name:
            labels = [lab for lab in name.split(".") if lab]
            if labels:
                base = ".".join(labels[-2:]) if len(labels) >= 2 else name
                queries_by_base[base].add(name)
                longest = max(labels, key=len)
                if (
                    len(longest) >= DGA_LABEL_LEN
                    and _entropy(longest) >= DGA_ENTROPY
                    and longest != base
                ):
                    dga_names.append((t, name))
                if ODD_LABEL_LEN <= len(longest) < 40:
                    odd.append((t, name))
        try:
            if qr == 1 and rcode == 3:
                nx_by_client[client or "?"].append(t)
        except Exception:
            continue

    for client, times in nx_by_client.items():
        times.sort()
        burst = False
        for i, start in enumerate(times):
            window = [x for x in times[i:] if x <= start + NXDOMAIN_WINDOW]
            if len(window) >= NXDOMAIN_COUNT:
                desc = (
                    f"{client} received {len(window)} NXDOMAIN answers "
                    f"in <= {NXDOMAIN_WINDOW:.0f}s"
                )
                events.append(
                    (
                        start,
                        "MEDIUM",
                        "NXDOMAIN burst",
                        desc,
                        "T1071.004 DNS",
                    )
                )
                findings.append(("MEDIUM", "NXDOMAIN burst", desc))
                add_ioc("ip", client, "NXDOMAIN burst source")
                burst = True
                break
        if burst:
            continue

    unique_dga = {n for _t, n in dga_names}
    if len(unique_dga) >= DGA_UNIQUE:
        sample = sorted(unique_dga, key=len)[-1]
        t0 = min(t for t, _n in dga_names)
        desc = (
            f"{len(unique_dga)} unique high-entropy DNS names "
            f"(simple DGA heuristic), e.g. {sample[:60]}"
        )
        events.append((t0, "HIGH", "Possible DGA", desc, "T1568.002 Domain Generation Algorithms"))
        findings.append(("HIGH", "Possible DGA activity", desc))
        for name in sorted(unique_dga)[:5]:
            add_ioc("domain", name, "DGA-like DNS name")

    for t, name in odd[:1]:
        desc = f"unusually long DNS label in {name[:80]}"
        events.append((t, "LOW", "Odd DNS name", desc, "T1071.004 DNS"))
        findings.append(("LOW", "Odd / long DNS name", desc))
        add_ioc("domain", name, "odd DNS name")

    for base, names in queries_by_base.items():
        if len(names) < TUNNEL_UNIQUE:
            continue
        # Many unique subdomains of one base is a tunnelling / staging sign
        # even when no single label hits the 40-char threshold.
        if any(len(n.split(".")[0]) >= 24 for n in names):
            sample = sorted(names, key=len)[-1]
            desc = (
                f"{len(names)} unique sub-domains of {base} "
                f"(DNS tunnelling sign), e.g. {sample[:60]}"
            )
            events.append(
                (
                    0.0,
                    "MEDIUM",
                    "DNS tunnelling signs",
                    desc,
                    "T1071.004 DNS / T1048",
                )
            )
            findings.append(("MEDIUM", "DNS tunnelling signs", desc))
            add_ioc("domain", base, "many unique subdomains")

    return findings, events, iocs
