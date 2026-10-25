"""Core PCAP analysis and detections (MITRE ATT&CK mapped)."""
from __future__ import annotations

import base64
import csv
import hashlib
import ipaddress
import json
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

from scapy.all import DNS, DNSQR, IP, TCP, IPv6

from pcaplens.custody import CustodyLog, hash_file, verify
from pcaplens.parse import DEFAULT_LIMITS, ParseLimits, PcapParseError, load_packets
from pcaplens.thresholds import Thresholds
from pcaplens.tls import extract_sni

# Bump this string when the --format json object shape changes in a
# breaking way (renamed, removed, or retyped fields). It is a string,
# not a number, so "1.0" and "1.10" stay distinct.
JSON_SCHEMA_VERSION = "1.0"

# Values --format / report_format accept. markdown stays the default so
# existing scripts keep writing report.md.
REPORT_FORMATS = ("markdown", "json")


def _unsupported_report_format(report_format: str) -> ValueError:
    allowed = " or ".join(repr(item) for item in REPORT_FORMATS)
    return ValueError(f"unsupported report format {report_format!r}; use {allowed}")


# Site/local prefixes for internal vs external (exfil) classification.
# IPv4: RFC 1918 only. Do not use ipaddress.is_private — it treats RFC 5737
# documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) as
# private, which would hide the lab "external" hosts used in tests.
# IPv6: RFC 4193 ULA (fc00::/7), link-local (fe80::/10), loopback (::1).
# is_internal unwraps IPv4-mapped IPv6 (::ffff:...) before checking this list.
INTERNAL_NETWORKS = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
        "fe80::/10",
        "::1/128",
    )
]
SCRIPTED_UA = re.compile(
    r"python-requests|curl/|wget/|powershell|go-http-client", re.I
)


def format_ts(t: float) -> str:
    return datetime.fromtimestamp(float(t), timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


def is_internal(ip: str) -> bool:
    """Return True if *ip* is a site/local address we treat as internal.

    IPv4 (and IPv4-mapped IPv6 such as ``::ffff:10.0.0.1``): RFC 1918 only.
    Loopback and RFC 5737 documentation ranges stay external.

    IPv6: RFC 4193 unique-local (``fc00::/7``), link-local (``fe80::/10``),
    and loopback (``::1``). A ``%zone`` suffix (``fe80::1%eth0``) is ignored
    because it names a local interface, not a different address.
    """
    # Some Python versions reject "fe80::1%eth0"; the zone is not the address.
    host = ip.rsplit("%", 1)[0]
    addr = ipaddress.ip_address(host)
    # ::ffff:x.x.x.x is IPv4 sitting on an IPv6 socket — use the IPv4 rules.
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return any(addr in network for network in INTERNAL_NETWORKS)


def l3_addrs(pkt: Any) -> tuple[str, str] | None:
    """Return (src, dst) from IPv4, or IPv6 if there is no IPv4 layer."""
    if IP in pkt:
        return pkt[IP].src, pkt[IP].dst
    if IPv6 in pkt:
        return pkt[IPv6].src, pkt[IPv6].dst
    return None


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


def reassemble(
    pkts: Any, max_stream_bytes: int = DEFAULT_LIMITS.max_stream_bytes
) -> tuple[dict, dict]:
    streams: dict = defaultdict(dict)
    first_seen: dict = {}
    sizes: dict = defaultdict(int)
    for p in pkts:
        try:
            addrs = l3_addrs(p)
            if not addrs or TCP not in p:
                continue
            src, dst = addrs
            key = (src, p[TCP].sport, dst, p[TCP].dport)
            first_seen.setdefault(key, float(p.time))
            payload = bytes(p[TCP].payload)
            seq = int(p[TCP].seq)
        except Exception:
            continue
        if not payload:
            continue
        # Retransmits share a seq; they must not spend the stream-size budget.
        if seq in streams[key]:
            continue
        if sizes[key] + len(payload) > max_stream_bytes:
            continue
        streams[key][seq] = payload
        sizes[key] += len(payload)
    return (
        {k: b"".join(v[s] for s in sorted(v)) for k, v in streams.items()},
        first_seen,
    )


def parse_http(
    data: bytes,
    *,
    max_body: int = DEFAULT_LIMITS.max_http_body_bytes,
    max_header: int = DEFAULT_LIMITS.max_http_header_bytes,
    max_messages: int = DEFAULT_LIMITS.max_http_messages,
) -> list[tuple[str, dict[str, str], bytes]]:
    """Split a byte string into HTTP messages. Never raises on bad input."""
    msgs: list = []
    i = 0
    while i < len(data) and len(msgs) < max_messages:
        end = data.find(b"\r\n\r\n", i)
        if end < 0:
            break
        if end - i > max_header:
            break
        head = data[i:end].decode("latin-1").split("\r\n")
        headers = {
            k.strip().lower(): v.strip()
            for k, _, v in (h.partition(":") for h in head[1:])
            if k.strip()
        }
        raw_len = headers.get("content-length", "0") or "0"
        # A 64 KiB string of digits would become a huge int. Real Content-Length
        # values fit in 16 digits (up to a petabyte).
        if len(raw_len) > 16:
            length = 0
        else:
            try:
                length = int(raw_len)
            except ValueError:
                length = 0
        if length < 0:
            length = 0
        available = len(data) - (end + 4)
        length = min(length, max_body, max(available, 0))
        body = data[end + 4 : end + 4 + length]
        msgs.append((head[0] if head else "", headers, body))
        nxt = end + 4 + length
        if nxt <= i:
            break
        i = nxt
    return msgs


def summarize_findings(findings: list[tuple[str, str, str]]) -> str:
    # INFO rows are observational context (e.g. TLS SNI), not detections.
    scored = [f for f in findings if f[0] != "INFO"]
    if not scored:
        return "No suspicious activity detected by the current rules."
    cats = Counter(t for _, t, _ in scored)
    worst = scored[0][0]
    lines = [
        f"{len(scored)} findings (highest severity {worst}): "
        + "; ".join(f"{c} x{n}" for c, n in cats.items())
        + "."
    ]
    recs = []
    if any("Executable" in t or "beacon" in t.lower() for _, t, _ in scored):
        recs.append("isolate the affected host and image disk + memory")
    if any("exfil" in t.lower() or "tunnel" in t.lower() for _, t, _ in scored):
        recs.append("block the listed domains/IPs and assess what data left")
    if any("credential" in t.lower() for _, t, _ in scored):
        recs.append(
            "reset exposed accounts and replace cleartext protocols (FTP -> SFTP)"
        )
    if any("scan" in t.lower() for _, t, _ in scored):
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
    tls_sni: list[tuple[str, str, int, str]] = field(default_factory=list)
    report_path: Path | None = None
    sha256: str = ""
    unchanged: bool = True
    cross_check: str = ""


def build_json_report(
    *,
    case_id: str,
    findings: list[tuple[str, str, str]],
    iocs: list[tuple[str, str, str]],
    custody_ok: bool,
    custody_summary: str,
    custody_entries: int,
    pcap_unchanged: bool,
    sha256: str,
) -> dict[str, Any]:
    """Build the versioned JSON report written by --format json.

    The object always has the same top-level keys so a parser can rely
    on them: schema_version, case_id, findings, iocs, custody.
    findings and iocs may be empty lists (a clean capture).
    """
    return {
        "schema_version": JSON_SCHEMA_VERSION,
        "case_id": case_id,
        # Each finding is the same (severity, title, detail) tuple the
        # Markdown table uses, just as an object instead of a row.
        "findings": [
            {"severity": severity, "title": title, "detail": detail}
            for severity, title, detail in findings
        ],
        # Same (type, value, context) rows as iocs.csv.
        "iocs": [
            {"type": kind, "value": value, "context": context}
            for kind, value, context in iocs
        ],
        "custody": {
            "summary": custody_summary,
            "intact": custody_ok,
            "entries": custody_entries,
            "pcap_unchanged": pcap_unchanged,
            "sha256": sha256,
        },
    }


def _dns_qname(pkt: Any, max_bytes: int) -> str | None:
    """Return a query name, or None if the DNS layer is missing / hostile."""
    try:
        if DNS not in pkt or pkt[DNS].qr != 0 or not pkt.haslayer(DNSQR):
            return None
        raw = pkt[DNSQR].qname
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


def analyze_pcap(
    pcap: str | Path,
    *,
    case_id: str = "CASE-001",
    examiner: str | None = None,
    out: str | Path = "output",
    tshark_cross_check: bool = True,
    thresholds: Thresholds | None = None,
    report_format: str = "markdown",
    limits: ParseLimits | None = None,
) -> AnalysisResult:
    """Analyse a PCAP offline; write report, CSVs, objects, custody log."""
    # Fail before deleting --out so a typo or a missing PCAP cannot
    # wipe a previous run.
    if report_format not in REPORT_FORMATS:
        raise _unsupported_report_format(report_format)
    limits = limits or DEFAULT_LIMITS
    pcap = Path(pcap)
    out = Path(out)
    # None means "use built-in defaults" so existing callers stay unchanged.
    # Named thr (not t) so it does not collide with packet timestamps.
    thr = thresholds if thresholds is not None else Thresholds()
    if not pcap.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap}")
    if not pcap.is_file():
        raise PcapParseError(f"PCAP path is not a regular file: {pcap}")
    pkts = load_packets(pcap, limits)
    if out.exists():
        shutil.rmtree(out)
    (out / "extracted_objects").mkdir(parents=True)

    log = CustodyLog(out / "chain_of_custody.jsonl", case_id, examiner)
    pre = hash_file(pcap)
    log.record("pcap_hashed_before_analysis", file=str(pcap.resolve()), **pre)
    t0, t1 = float(pkts[0].time), float(pkts[-1].time)
    events: list = []
    iocs: list = []
    findings: list = []

    def event(t: float, sev: str, cat: str, desc: str, attack: str = "") -> None:
        events.append((float(t), sev, cat, desc, attack))

    def ioc(kind: str, value: str, context: str) -> None:
        if (kind, value) not in {(k, v) for k, v, _ in iocs}:
            iocs.append((kind, value, context))

    def http_messages(blob: bytes) -> list:
        return parse_http(
            blob,
            max_body=limits.max_http_body_bytes,
            max_header=limits.max_http_header_bytes,
            max_messages=limits.max_http_messages,
        )

    talk: Counter = Counter()
    for p in pkts:
        try:
            addrs = l3_addrs(p)
            if addrs:
                talk[addrs] += len(p)
        except Exception:
            continue

    syns: dict = defaultdict(list)
    for p in pkts:
        try:
            addrs = l3_addrs(p)
            if addrs and TCP in p and p[TCP].flags == "S":
                syns[addrs].append((float(p.time), p[TCP].dport))
        except Exception:
            continue

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
                        and p[TCP].flags == "SA"
                        and l3_addrs(p) == (dst, src)
                    }
                )
                desc = (
                    f"{src} probed {len(window)} ports on {dst} "
                    f"in <= {thr.SCAN_WINDOW}s (open: {open_ports})"
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
        # Need two timestamps to form a gap; a bad Thresholds object must not crash.
        if len(times) < max(thr.BEACON_MIN_CONNS, 2):
            continue
        times.sort()
        gaps = [b - a for a, b in zip(times, times[1:], strict=False)]
        med = statistics.median(gaps)
        regular = [g for g in gaps if abs(g - med) <= thr.BEACON_TOLERANCE * med]
        ratio = len(regular) / len(gaps)
        if med > 0 and ratio >= thr.BEACON_MIN_RATIO:
            jitter = statistics.pstdev(regular) if len(regular) > 1 else 0.0
            desc = (
                f"{src} -> {dst}:{port} {len(times)} connections, "
                f"median interval {med:.1f}s, {ratio:.0%} of intervals "
                f"within +-{thr.BEACON_TOLERANCE:.0%} (jitter {jitter:.1f}s)"
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
        q = _dns_qname(p, limits.max_dns_name_bytes)
        if not q:
            continue
        labels = q.split(".")
        base = ".".join(labels[-2:]) if len(labels) >= 2 else q
        dns_by_domain[base].add(q)
        longest = max(labels, key=len)
        if len(longest) >= thr.DNS_LABEL_LEN and entropy(longest) >= thr.DNS_ENTROPY:
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
        first_times = []
        for p in pkts:
            qn = _dns_qname(p, limits.max_dns_name_bytes)
            if qn and base in qn:
                try:
                    first_times.append(float(p.time))
                except Exception:
                    continue
        first = min(first_times) if first_times else t0
        event(
            first,
            "HIGH",
            "DNS tunnelling",
            desc,
            "T1071.004 DNS / T1048 Exfiltration Over Alternative Protocol",
        )
        findings.append(("HIGH", "DNS tunnelling / exfiltration", desc))
        ioc("domain", base, "DNS tunnelling")

    streams, first_seen = reassemble(pkts, max_stream_bytes=limits.max_stream_bytes)
    obj_n = 0
    # Reconnects share a dest; SNI rows ignore the client port (sport).
    seen_sni: set[tuple[str, str, int, str]] = set()
    for (src, sport, dst, dport), data in streams.items():
        t = first_seen[(src, sport, dst, dport)]
        # ClientHello is the first bytes of the client->server stream.
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
                # Benign SNI is host-visit context, not a finding or IOC.
        if is_internal(src) and not is_internal(dst) and len(data) >= thr.EXFIL_BYTES:
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
            for start, headers, body in http_messages(data):
                if start.startswith(("GET", "POST", "PUT", "HEAD")):
                    parts = start.split()
                    if len(parts) < 2:
                        continue
                    method, uri = parts[0], parts[1]
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
                    reqs = []
                    for m in http_messages(rev):
                        req_parts = m[0].split()
                        if len(req_parts) >= 2 and req_parts[0] in ("GET", "POST"):
                            reqs.append((req_parts, m[1]))
                    if reqs:
                        uri = reqs[0][0][1]
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
    custody_path = out / "chain_of_custody.jsonl"
    custody_ok, chain = verify(custody_path)
    # verify() already walked the file; count lines for the JSON summary.
    custody_entries = sum(1 for line in custody_path.read_text().splitlines() if line.strip())

    # CSVs and the custody log are already on disk. Only the report
    # filename changes: report.json vs report.md.
    if report_format == "json":
        report_path = out / "report.json"
        payload = build_json_report(
            case_id=case_id,
            findings=findings,
            iocs=iocs,
            custody_ok=custody_ok,
            custody_summary=chain,
            custody_entries=custody_entries,
            pcap_unchanged=unchanged,
            sha256=pre["sha256"],
        )
        report_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    elif report_format == "markdown":
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
            "## TLS SNI (informational)",
            "",
            "Hostnames from TLS ClientHello. These are visited-site context, "
            "not findings or indicators of compromise.",
            "",
            "| Client | Server | Port | Hostname |",
            "|---|---|---|---|",
        ]
        sni_rows = [
            f"| {src} | {dst} | {dport} | `{host}` |"
            for src, dst, dport, host in sorted(seen_sni)
        ]
        md += sni_rows or ["| — | — | — | none observed |"]
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
    else:
        raise _unsupported_report_format(report_format)

    return AnalysisResult(
        packets=len(pkts),
        findings=findings,
        iocs=iocs,
        events=events,
        tls_sni=sorted(seen_sni),
        report_path=report_path,
        sha256=pre["sha256"],
        unchanged=unchanged,
        cross_check=cross,
    )
