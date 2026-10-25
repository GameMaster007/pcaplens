"""HTTP triage: scripted user-agents, suspicious URLs, hashed downloads."""
from __future__ import annotations

import hashlib
import re

from pcaplens.parse import DEFAULT_LIMITS

# Scripted / non-browser clients. One finding per unique UA, not per request.
SCRIPTED_UA = re.compile(
    r"python-requests|curl/|wget/|powershell|go-http-client", re.I
)

# Paths and query strings that are leads. Ordinary browsing must not match.
SUSPICIOUS_URI = re.compile(
    r"(?:"
    r"\.(?:exe|dll|ps1|bat|cmd|scr|msi)(?:\?|$)"
    r"|/(?:admin(?:istrator)?|wp-admin|wp-login\.php|phpmyadmin|shell)(?:/|\?|$)"
    r"|[?&](?:cmd|exec|eval|download|file)="
    r")",
    re.I,
)

# Notable response bodies get a hash IOC. HTML/text stays context only.
NOTABLE_KINDS = frozenset(
    {"windows-executable", "elf-executable", "pdf", "zip/office", "binary"}
)

# Executables stay the CRITICAL finding in analyze_pcap; this module
# records the hash and does not emit a second executable finding.
EXECUTABLE_KINDS = frozenset({"windows-executable", "elf-executable"})


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


def analyze_http(
    streams: dict,
    first_seen: dict,
    *,
    max_body: int = DEFAULT_LIMITS.max_http_body_bytes,
    max_header: int = DEFAULT_LIMITS.max_http_header_bytes,
    max_messages: int = DEFAULT_LIMITS.max_http_messages,
) -> tuple[list[tuple[str, str, str]], list[tuple], list[tuple[str, str, str]]]:
    """Return (findings, events, iocs) for HTTP heuristics.

    Existing executable-download and Basic-auth detections in analyze_pcap
    still run. This module adds scripted UAs, suspicious URLs, and hashed
    file downloads (non-executable notable types).
    """
    findings: list[tuple[str, str, str]] = []
    events: list[tuple] = []
    iocs: list[tuple[str, str, str]] = []
    seen_ioc: set[tuple[str, str]] = set()
    seen_ua: set[str] = set()
    seen_url: set[str] = set()
    seen_dl: set[str] = set()

    def add_ioc(kind: str, value: str, context: str) -> None:
        if (kind, value) in seen_ioc:
            return
        seen_ioc.add((kind, value))
        iocs.append((kind, value, context))

    for (src, sport, dst, dport), data in streams.items():
        try:
            t = float(first_seen.get((src, sport, dst, dport), 0.0))
        except (TypeError, ValueError):
            t = 0.0
        if not (
            data[:4] in (b"GET ", b"POST", b"HEAD", b"PUT ")
            or data.startswith(b"HTTP/")
        ):
            continue
        last_req = (dst, "/", "", "")
        for start, headers, body in parse_http(
            data,
            max_body=max_body,
            max_header=max_header,
            max_messages=max_messages,
        ):
            if start.startswith(("GET", "POST", "PUT", "HEAD")):
                parts = start.split()
                if len(parts) < 2:
                    continue
                method, uri = parts[0], parts[1]
                host = headers.get("host", dst)
                ua = headers.get("user-agent", "")
                last_req = (host, uri, method, ua)
                url = f"http://{host}{uri}"
                if ua and SCRIPTED_UA.search(ua) and ua not in seen_ua:
                    seen_ua.add(ua)
                    desc = f"{src} used scripted User-Agent '{ua}'"
                    events.append(
                        (t, "LOW", "Scripted user-agent", desc, "T1071.001 Web")
                    )
                    findings.append(("LOW", "Scripted HTTP user-agent", desc))
                    add_ioc("user-agent", ua, f"scripted client on {src}")
                if SUSPICIOUS_URI.search(uri) and url not in seen_url:
                    seen_url.add(url)
                    desc = f"{src} requested {method} {url}"
                    events.append(
                        (
                            t,
                            "MEDIUM",
                            "Suspicious HTTP URL",
                            desc,
                            "T1071.001 Web / T1105",
                        )
                    )
                    findings.append(("MEDIUM", "Suspicious HTTP URL", desc))
                    add_ioc("url", url, "suspicious HTTP path")
            elif start.startswith("HTTP/") and body:
                host, uri, _method, _ua = last_req
                rev = streams.get((dst, dport, src, sport), b"")
                for msg_start, msg_headers, _msg_body in parse_http(
                    rev,
                    max_body=max_body,
                    max_header=max_header,
                    max_messages=max_messages,
                ):
                    req_parts = msg_start.split()
                    if len(req_parts) >= 2 and req_parts[0] in (
                        "GET",
                        "POST",
                        "PUT",
                        "HEAD",
                    ):
                        uri = req_parts[1]
                        host = msg_headers.get("host", src)
                        break
                kind = sniff_type(body)
                sha = hashlib.sha256(body).hexdigest()
                if kind not in NOTABLE_KINDS or sha in seen_dl:
                    continue
                seen_dl.add(sha)
                name = uri.split("?")[0].rsplit("/", 1)[-1] or "object"
                add_ioc("sha256", sha, f"downloaded {name} ({kind})")
                add_ioc("url", f"http://{host}{uri}", f"{kind} download")
                if kind in EXECUTABLE_KINDS:
                    # analyze_pcap already emits CRITICAL executable download.
                    continue
                desc = (
                    f"{dst} downloaded {kind} {uri} from {host} ({src}), "
                    f"{len(body)} bytes, SHA-256 {sha}"
                )
                events.append(
                    (
                        t,
                        "LOW",
                        "HTTP file download",
                        desc,
                        "T1105 Ingress Tool Transfer",
                    )
                )
                findings.append(("LOW", "HTTP file download", desc))

    return findings, events, iocs
