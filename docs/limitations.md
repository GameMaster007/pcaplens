# What pcaplens does not detect

Honest scope for a viva or a SOC hand-off. Findings are **leads**, not
proof. See [docs/viva.md](viva.md) for why the rules look this way.

## Out of scope

pcaplens does **not**:

- Decrypt TLS, QUIC, or any other encrypted payload. SNI is read from
  a cleartext ClientHello only. Encrypted Client Hello (ECH) yields no
  hostname.
- Fingerprint TLS (JA3 / JA4) or identify a malware family / C2 implant.
- Parse HTTP/2, HTTP/3, or QUIC. Cleartext HTTP/1.x only.
- See DNS-over-HTTPS or DNS-over-TLS as DNS. Those look like HTTPS.
- Unwrap tunnels: GRE, IPsec, VXLAN, Geneve, or VLAN (`802.1Q`).
  Unknown link types are treated as Ethernet; a VLAN-tagged frame may
  not expose IPv4/IPv6 to the detectors.
- Analyse SMTP, SMB, RDP, SSH, ICMP, or DHCP beyond “bytes on the wire”.
- Detect UDP or ICMP port scans. Scan heuristics are TCP SYN only.
- Carve files except HTTP/1 request and response bodies.
- Reconstruct overlapping TCP segments, IP fragments, or a mid-stream
  capture the way Wireshark does. Reassembly is a sequence-number map;
  retransmits are ignored.
- Run as a live IDS. One offline file in, one report out.
- Meet the UK Forensic Science Regulator Code. It is a teaching /
  triage tool, not an accredited method.

Internal vs external is RFC 1918 IPv4 (plus IPv4-mapped IPv6) and IPv6
ULA / link-local / loopback. RFC 5737 documentation ranges and
`2001:db8::/32` count as **external** on purpose (lab “internet”).

## Known false positives

These still fire after the Round 2 threshold raise. Tune `--profile`
on a clean baseline before trusting them on a production LAN.

| Heuristic | When it lies |
|-----------|----------------|
| C2 beaconing | Software updaters and polling agents with ≥6 regular SYNs and low jitter. A median gap test still looks like C2 if the updater is metronomic. |
| DNS tunnelling | A CDN or cache-buster label ≥ 40 characters with entropy ≥ 3.5. The base32 decode is a lab convenience and will happily decode garbage. |
| DGA | A capture that really does mint ≥ 20 unique high-entropy labels (some ad / telemetry CDNs). The cut-off was 12 names; that was too eager. |
| Scripted User-Agent | `curl`, `wget`, `python-requests`, PowerShell, `Go-http-client` used by an admin or a CI job. Always LOW. |
| Exfiltration | Any internal→external TCP stream ≥ 100 KiB (ISO, backup, cloud sync). |
| Horizontal scan | Many hosts on a *non-web* port, or web ports with a low completed-handshake ratio. Ordinary 80/443 browsing is skipped when the handshake completes. |
| RFC 5737 / `2001:db8::` | Lab “external” hosts. Intentional so exfil and scan tests have an internet. |

Benign fixtures that must stay clean (no finding above INFO):
`samples/fixtures/clean_browse.pcap`, plus the synthetic browsing /
office-DNS / software-update / streaming builders in tests.

## Known false negatives

| Miss | Why |
|------|-----|
| Slow or targeted scan | Fewer than 50 distinct SYN dports in 60s, or a connect-scan (`-sT`) with > 20% completed handshakes. |
| SYN scan that succeeds | Half-open detector requires many SYN-only probes. A scanner that finishes the handshake looks like a client. |
| Short-label DNS tunnel | Labels under 40 characters (main tunnel rule) or under 12 / fewer than 20 unique names (DGA) or 16 subdomains (tunnelling-signs). |
| Jittered C2 | Gaps outside ±10% of the median, or fewer than six SYNs, or a single stream instead of reconnects. |
| Small or split exfil | Under 100 KiB, or the same bytes split across reconnects (each stream is scored alone). |
| HTTPS malware | Payload is opaque. Beaconing still fires if reconnects are regular; SNI is context only and is **not** a finding. |
| Encrypted SNI / ECH | No hostname is extracted. |
| DoH / DoT C2 | Seen as HTTPS, not DNS. |
| HTTP/2 or QUIC download | No HTTP/1 parser match, so no executable-download finding. |
| VLAN / tunnel inner host | Link decode never reaches the inner IP. |
| Mid-stream or heavily lossy capture | Handshake or first HTTP request never seen. |

Default caps also hide traffic: 250 000 packets or 512 MiB (`--max-packets` /
`--max-file-bytes`), 8 MiB per TCP stream, 4 MiB per HTTP body. A capture
over the cap exits 2 rather than analysing a prefix.

## How to talk about this in a viva

- “What do you *not* catch?” — encrypted payloads, HTTP/2/QUIC, DoH,
  VLAN/tunnels, slow scans, jittered C2. Point at this file.
- “Will a Windows Update look like DGA?” — not with the current
  cut-offs; the software-update fixture is the regression test. A
  noisier CDN still might.
- “Is a clean report a clean network?” — no. It is “no rule fired”.
- “Why is SNI not an IOC?” — every HTTPS visit would become an
  indicator. SNI is timeline context; see [docs/viva.md](viva.md).
