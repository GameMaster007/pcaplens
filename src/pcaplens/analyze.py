"""Core PCAP analysis and detections (MITRE ATT&CK mapped)."""
from __future__ import annotations

import base64
import csv
import hashlib
import ipaddress
import math
import re
import shutil
import statistics
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scapy.all import DNS, DNSQR, IP, TCP, rdpcap

from pcaplens import thresholds as T
from pcaplens.custody import CustodyLog, hash_file, verify
from pcaplens.tls import extract_sni

RFC1918 = [
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
]
SCRIPTED_UA = re.compile(
    r"python-requests|curl/|wget/|powershell|go-http-client", re.I
)


def format_ts(t: float) -> str:
    return datetime.fromtimestamp(float(t), timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


def is_internal(ip: str) -> bool:
    # Do not use ipaddress.is_private: it treats RFC 5737 docs ranges as private.
    return any(ipaddress.ip_address(ip) in n for n in RFC1918)


def entropy(s: str) -> float:
    c = Counter(s)
    return (
        -sum(n / len(s) * math.log2(n / len(s)) for n in c.values()) if s else 0.0
    )


def sniff_type(data: bytes) -> str:
    for magic, name in (
        (b"MZ", "windows-executable"),
        (b"\x7fELF", "elf-executable"),
        (b"%PDF", "pdf"),
        (b"PK\x03\x04", "zip/office"),
        (b"\xff\xd8\xff", "jpeg"),
        (b"<html", "html"),
        (b"<!doctype", "html"),
    ):
        if data[: len(magic)].lower() == magic.lower():
            return name
    try:
        data[:512].decode("ascii")
        return "text"
    except UnicodeDecodeError:
        return "binary"


def reassemble(pkts: Any) -> tuple[dict, dict]:
    streams: dict = defaultdict(dict)
    first_seen: dict = {}
    for p in pkts:
        if IP in p and TCP in p:
            key = (p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport)
            first_seen.setdefault(key, float(p.time))
            payload = bytes(p[TCP].payload)
            if payload:
                streams[key].setdefault(p[TCP].seq, payload)
    return (
        {k: b"".join(v[s] for s in sorted(v)) for k, v in streams.items()},
        first_seen,
    )


def parse_http(data: bytes) -> list[tuple[str, dict[str, str], bytes]]:
    msgs: list = []
    i = 0
    while i < len(data):
        end = data.find(b"\r\n\r\n", i)
        if end < 0:
            break
        head = data[i:end].decode("latin-1").split("\r\n")
        headers = {
            k.strip().lower(): v.strip()
            for k, _, v in (h.partition(":") for h in head[1:])
        }
        length = int(headers.get("content-length", 0) or 0)
        body = data[end + 4 : end + 4 + length]
        msgs.append((head[0], headers, body))
        i = end + 4 + length
    return msgs


def summarize_findings(findings: list[tuple[str, str, str]]) -> str:
    if not findings:
        return "No suspicious activity detected by the current rules."
    cats = Counter(t for _, t, _ in findings)
    worst = findings[0][0]
    lines = [
        f"{len(findings)} findings (highest severity {worst}): "
        + "; ".join(f"{c} x{n}" for c, n in cats.items())
        + "."
    ]
    recs = []
    if any("Executable" in t or "beacon" in t.lower() for _, t, _ in findings):
        recs.append("isolate the affected host and image disk + memory")
    if any("exfil" in t.lower() or "tunnel" in t.lower() for _, t, _ in findings):
        recs.append("block the listed domains/IPs and assess what data left")
    if any("credential" in t.lower() for _, t, _ in findings):
        recs.append(
            "reset exposed accounts and replace cleartext protocols (FTP -> SFTP)"
        )
    if any("scan" in t.lower() for _, t, _ in findings):
        recs.append("identify who/what ran the scan from the internal host")
    return lines[0] + (
        " Recommended actions: " + "; ".join(recs) + "." if recs else ""
    )


@dataclass
class AnalysisResult:
    packets: int
    findings: list[tuple[str, str, str]] = field(default_factory=list)
    iocs: list[tuple[str, str, str]] = field(default_factory=list)
    events: list[tuple] = field(default_factory=list)
    report_path: Path | None = None
    sha256: str = ""
    unchanged: bool = True
    cross_check: str = ""


def analyze_pcap(
    pcap: str | Path,
    *,
    case_id: str = "CASE-001",
    examiner: str | None = None,
    out: str | Path = "output",
    tshark_cross_check: bool = True,
) -> AnalysisResult:
    """Analyse a PCAP offline; write report.md, CSVs, objects, custody log."""
    pcap = Path(pcap)
    out = Path(out)
    if out.exists():
        shutil.rmtree(out)
    (out / "extracted_objects").mkdir(parents=True)

    log = CustodyLog(out / "chain_of_custody.jsonl", case_id, examiner)
    pre = hash_file(pcap)
    log.record("pcap_hashed_before_analysis", file=str(pcap.resolve()), **pre)

    pkts = rdpcap(str(pcap))
    if not pkts:
        raise ValueError("PCAP contains no packets")
    t0, t1 = float(pkts[0].time), float(pkts[-1].time)
    events: list = []
    iocs: list = []
    findings: list = []

    def event(t: float, sev: str, cat: str, desc: str, attack: str = "") -> None:
        events.append((float(t), sev, cat, desc, attack))

    def ioc(kind: str, value: str, context: str) -> None:
        if (kind, value) not in {(k, v) for k, v, _ in iocs}:
            iocs.append((kind, value, context))

    talk: Counter = Counter()
    for p in pkts:
        if IP in p:
            talk[(p[IP].src, p[IP].dst)] += len(p)

    syns: dict = defaultdict(list)
    for p in pkts:
        if IP in p and TCP in p and p[TCP].flags == "S":
            syns[(p[IP].src, p[IP].dst)].append((float(p.time), p[TCP].dport))

    for (src, dst), lst in syns.items():
        lst.sort()
        for i in range(len(lst)):
            window = {
                port
                for t, port in lst
                if lst[i][0] <= t <= lst[i][0] + T.SCAN_WINDOW
            }
            if len(window) >= T.SCAN_PORTS:
                open_ports = sorted(
                    {
                        p[TCP].sport
                        for p in pkts
                        if IP in p
                        and TCP in p
                        and p[IP].src == dst
                        and p[IP].dst == src
                        and p[TCP].flags == "SA"
                    }
                )
                desc = (
                    f"{src} probed {len(window)} ports on {dst} "
                    f"in <= {T.SCAN_WINDOW}s (open: {open_ports})"
                )
                event(
                    lst[i][0],
                    "HIGH",
                    "Port scan",
                    desc,
                    "T1046 Network Service Discovery",
                )
                findings.append(("HIGH", "Port scan", desc))
                ioc("ip", src, "internal scanning host")
                break

    conns: dict = defaultdict(list)
    for (src, dst), lst in syns.items():
        for t, port in lst:
            conns[(src, dst, port)].append(t)
    for (src, dst, port), times in conns.items():
        if len(times) < T.BEACON_MIN_CONNS:
            continue
        times.sort()
        gaps = [b - a for a, b in zip(times, times[1:], strict=False)]
        med = statistics.median(gaps)
        regular = [g for g in gaps if abs(g - med) <= T.BEACON_TOLERANCE * med]
        ratio = len(regular) / len(gaps)
        if med > 0 and ratio >= T.BEACON_MIN_RATIO:
            jitter = statistics.pstdev(regular) if len(regular) > 1 else 0.0
            desc = (
                f"{src} -> {dst}:{port} {len(times)} connections, "
                f"median interval {med:.1f}s, {ratio:.0%} of intervals "
                f"within +-10% (jitter {jitter:.1f}s)"
            )
            event(
                times[0],
                "HIGH",
                "C2 beaconing",
                desc,
                "T1071.001 Application Layer Protocol: Web",
            )
            findings.append(("HIGH", "Likely C2 beaconing", desc))
            ioc("ip", dst, f"beacon destination port {port}")

    dns_by_domain: dict = defaultdict(set)
    for p in pkts:
        if DNS in p and p[DNS].qr == 0 and p.haslayer(DNSQR):
            q = p[DNSQR].qname.decode(errors="replace").rstrip(".")
            labels = q.split(".")
            base = ".".join(labels[-2:]) if len(labels) >= 2 else q
            dns_by_domain[base].add(q)
            longest = max(labels, key=len)
            if len(longest) >= T.DNS_LABEL_LEN and entropy(longest) >= T.DNS_ENTROPY:
                dns_by_domain[base].add("__suspicious__")
    for base, names in dns_by_domain.items():
        if "__suspicious__" not in names:
            continue
        names.discard("__suspicious__")
        sample = sorted(names, key=len)[-1]
        decoded = ""
        try:
            chunks = sorted(
                (n for n in names if n.endswith(base)),
                key=lambda n: int(n.split(".")[1]),
            )
            enc = "".join(n.split(".")[0] for n in chunks).upper()
            decoded = base64.b32decode(
                enc + "=" * (-len(enc) % 8)
            ).decode("utf-8", "replace")[:80]
        except Exception:
            pass
        desc = (
            f"{len(names)} unique long/high-entropy sub-domains of {base}, "
            f"e.g. {sample[:60]}..."
            + (f" decoded (base32): '{decoded}...'" if decoded else "")
        )
        first = min(
            float(p.time)
            for p in pkts
            if DNS in p
            and p.haslayer(DNSQR)
            and base in p[DNSQR].qname.decode(errors="replace")
        )
        event(
            first,
            "HIGH",
            "DNS tunnelling",
            desc,
            "T1071.004 DNS / T1048 Exfiltration Over Alternative Protocol",
        )
        findings.append(("HIGH", "DNS tunnelling / exfiltration", desc))
        ioc("domain", base, "DNS tunnelling")

    streams, first_seen = reassemble(pkts)
    obj_n = 0
    seen_sni: set[tuple[str, str, int, str]] = set()
    for (src, sport, dst, dport), data in streams.items():
        t = first_seen[(src, sport, dst, dport)]
        # ClientHello sits at the start of the client->server stream (no decrypt).
        sni = extract_sni(data)
        if sni:
            flow = (src, dst, dport, sni)
            if flow not in seen_sni:
                seen_sni.add(flow)
                desc = f"{src} -> {dst}:{dport} TLS SNI '{sni}'"
                event(
                    t,
                    "INFO",
                    "TLS SNI",
                    desc,
                    "T1573 Encrypted Channel",
                )
                findings.append(("INFO", "TLS SNI", desc))
                ioc("domain", sni, f"TLS SNI on {dst}:{dport}")
        if is_internal(src) and not is_internal(dst) and len(data) >= T.EXFIL_BYTES:
            desc = f"{src} sent {len(data):,} bytes to {dst}:{dport} in one stream"
            event(
                t,
                "HIGH",
                "Large outbound transfer",
                desc,
                "T1041 Exfiltration Over C2 Channel",
            )
            findings.append(("HIGH", "Possible data exfiltration", desc))
            ioc("ip", dst, "exfiltration destination")
        if dport == 21:
            text = data.decode("latin-1")
            user = re.search(r"USER (\S+)", text)
            pw = re.search(r"PASS (\S+)", text)
            if user:
                masked = (
                    (pw.group(1)[:2] + "*" * (len(pw.group(1)) - 2))
                    if pw
                    else "(none)"
                )
                desc = (
                    f"FTP login from {src} to {dst}: user '{user.group(1)}', "
                    f"password '{masked}' sent in cleartext"
                )
                event(
                    t,
                    "MEDIUM",
                    "Cleartext credentials",
                    desc,
                    "T1552 Unsecured Credentials (exposure via T1040 sniffing)",
                )
                findings.append(
                    ("MEDIUM", "Cleartext credentials on the wire", desc)
                )
        if data[:4] in (b"GET ", b"POST", b"HEAD", b"PUT ") or data.startswith(
            b"HTTP/"
        ):
            last_req = (src, "/")
            for start, headers, body in parse_http(data):
                if start.startswith(("GET", "POST", "PUT", "HEAD")):
                    method, uri = start.split(" ")[:2]
                    host = headers.get("host", dst)
                    ua = headers.get("user-agent", "")
                    event(
                        t,
                        "INFO",
                        "HTTP request",
                        f"{src} {method} http://{host}{uri} UA='{ua}'",
                    )
                    if SCRIPTED_UA.search(ua):
                        ioc("user-agent", ua, f"scripted client on {src}")
                    if headers.get("authorization", "").lower().startswith("basic"):
                        findings.append(
                            (
                                "MEDIUM",
                                "HTTP Basic auth in cleartext",
                                f"{src} -> {host}",
                            )
                        )
                    last_req = (host, uri)
                    if body:
                        obj_n += 1
                        fname = f"{obj_n:03d}_upload_from_{src}"
                        (out / "extracted_objects" / fname).write_bytes(body)
                        with open(
                            out / "extracted_objects" / "objects.sha256", "a"
                        ) as fh:
                            fh.write(
                                f"{hashlib.sha256(body).hexdigest()}  {fname}  "
                                f"({sniff_type(body)}, {method} to {host}{uri})\n"
                            )
                elif start.startswith("HTTP/") and body:
                    obj_n += 1
                    host, uri = last_req
                    rev = streams.get((dst, dport, src, sport), b"")
                    reqs = [
                        m
                        for m in parse_http(rev)
                        if m[0].split(" ")[0] in ("GET", "POST")
                    ]
                    if reqs:
                        uri = reqs[0][0].split(" ")[1]
                        host = reqs[0][1].get("host", src)
                    name = (
                        re.sub(
                            r"[^\w.-]",
                            "_",
                            uri.split("?")[0].rsplit("/", 1)[-1] or "index",
                        )
                        or "object"
                    )
                    fname = f"{obj_n:03d}_{name}"
                    (out / "extracted_objects" / fname).write_bytes(body)
                    kind = sniff_type(body)
                    sha = hashlib.sha256(body).hexdigest()
                    if kind.endswith("executable"):
                        desc = (
                            f"{dst} downloaded {kind} {uri} from {host} ({src}), "
                            f"{len(body)} bytes, SHA-256 {sha}"
                        )
                        event(
                            t,
                            "CRITICAL",
                            "Executable download",
                            desc,
                            "T1105 Ingress Tool Transfer",
                        )
                        findings.append(
                            ("CRITICAL", "Executable downloaded over HTTP", desc)
                        )
                        ioc("sha256", sha, f"downloaded {name}")
                        ioc("domain", host, "served executable")
                        ioc("url", f"http://{host}{uri}", "executable download")
                    with open(
                        out / "extracted_objects" / "objects.sha256", "a"
                    ) as fh:
                        fh.write(f"{sha}  {fname}  ({kind}, from {host}{uri})\n")

    log.record(
        "analysis_complete",
        packets=len(pkts),
        streams=len(streams),
        objects=obj_n,
        findings=len(findings),
    )

    cross = "tshark not installed - skipped"
    if tshark_cross_check and shutil.which("tshark"):
        tdir = out / "tshark_export"
        subprocess.run(
            ["tshark", "-r", str(pcap), "-q", "--export-objects", f"http,{tdir}"],
            capture_output=True,
            check=False,
        )
        n = len(list(tdir.iterdir())) if tdir.exists() else 0
        cross = (
            f"tshark --export-objects found {n} HTTP objects; "
            f"this tool extracted {obj_n}"
        )
        shutil.rmtree(tdir, ignore_errors=True)
    log.record("tool_cross_check", result=cross)

    post = hash_file(pcap)
    unchanged = pre == post
    log.record("pcap_hashed_after_analysis", unchanged=unchanged, **post)

    events.sort()
    with open(out / "events.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(
            ["time_utc", "severity", "category", "description", "mitre_attack"]
        )
        w.writerows([(format_ts(e[0]),) + e[1:] for e in events])
    with open(out / "iocs.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["type", "value", "context"])
        w.writerows(iocs)

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: order.get(f[0], 9))
    _, chain = verify(out / "chain_of_custody.jsonl")

    md = [
        f"# Network Forensics Report - {case_id}",
        "",
        "## Evidence",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Capture | `{pcap.name}` ({pcap.stat().st_size:,} bytes) |",
        f"| SHA-256 | `{pre['sha256']}` |",
        f"| Unchanged after analysis | {'YES' if unchanged else 'NO'} |",
        f"| Packets | {len(pkts)} |",
        f"| Time span | {format_ts(t0)} to {format_ts(t1)} |",
        f"| Custody log | {chain} |",
        f"| Cross-check | {cross} |",
        "",
        "## Executive summary",
        "",
        summarize_findings(findings),
        "",
        "## Findings",
        "",
        "| Severity | Finding | Detail |",
        "|---|---|---|",
    ]
    md += [f"| {s} | {t} | {d} |" for s, t, d in findings]
    md += [
        "",
        "## Timeline (non-informational events)",
        "",
        "| Time | Sev | Category | Detail | ATT&CK |",
        "|---|---|---|---|---|",
    ]
    md += [
        f"| {format_ts(e[0])} | {e[1]} | {e[2]} | {e[3]} | {e[4]} |"
        for e in events
        if e[1] != "INFO"
    ]
    md += [
        "",
        "## Indicators of compromise",
        "",
        "| Type | Value | Context |",
        "|---|---|---|",
    ]
    md += [f"| {k} | `{v}` | {c} |" for k, v, c in iocs]
    md += [
        "",
        "## Top talkers (bytes)",
        "",
        "| Source | Destination | Bytes |",
        "|---|---|---|",
    ]
    md += [f"| {s} | {d} | {b:,} |" for (s, d), b in talk.most_common(8)]
    md += [
        "",
        "## Limitations",
        "",
        "- Heuristic thresholds need baselining on real networks to cut false positives.",
        "- Encrypted traffic (TLS/HTTPS) hides payloads; SNI is read from ClientHello (no decrypt).",
        "- Passwords are masked in this report; full values stay only in the original evidence.",
        "- Generated by [pcaplens](https://github.com/GameMaster007/pcaplens).",
    ]
    report_path = out / "report.md"
    report_path.write_text("\n".join(md) + "\n", encoding="utf-8")

    return AnalysisResult(
        packets=len(pkts),
        findings=findings,
        iocs=iocs,
        events=events,
        report_path=report_path,
        sha256=pre["sha256"],
        unchanged=unchanged,
        cross_check=cross,
    )
