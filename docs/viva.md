# How it works / viva answers

Short defence of the design. Heuristics are **leads**, not proof.

## What pcaplens is

Offline PCAP triage: one capture in, a severity-ranked report, IOC table,
timeline, extracted HTTP objects, and a hash-chained custody log out.
Every scored finding maps to a MITRE ATT&CK technique. It is not a
Wireshark replacement, not a full IDS, and not an accredited method
under the UK Forensic Science Regulator Code.

## Pipeline

1. **Fail closed on the file.** Missing path → `FileNotFoundError`.
   Directory / non-file → `PcapParseError`. Size and packet-count
   limits apply before analysis. `--out` is not deleted until the
   capture is readable.
2. **Parse.** Classic PCAP or PCAPng. Block `Total Length` is checked
   against remaining bytes (a 120-byte file that claims a 2 GiB block
   is rejected without allocating). Packet-size limits use **captured**
   length (`incl_len` / `caplen`), not on-wire `orig_len` / `wirelen`.
   Linux cooked captures (`LINKTYPE_LINUX_SLL` / `SLL2`, `tcpdump -i any`)
   and DLT_RAW IPv6 are decoded.
3. **Ingest once.** Scapy frames are turned into compact TCP/DNS facts
   and dropped. Default cap is 250 000 packets / 512 MiB; override with
   `--max-packets` / `--max-file-bytes`. A 1M-packet synthetic file is
   streamed in CI.
4. **Reassemble TCP** by sequence number. Retransmits share a seq and
   do not spend the stream-size budget.
5. **Detect.** Independent modules (scan, DNS, HTTP, beacon, exfil,
   FTP, TLS SNI) append findings / events / IOCs.
6. **Write.** Markdown or JSON report, `events.csv`, `iocs.csv`,
   `extracted_objects/`, `chain_of_custody.jsonl`. Pre- and post-hash
   of the PCAP must match. JSON is checked against schema 1.0 before
   write.

## Why these detection choices

**Beaconing uses the median gap**, not mean/stdev. One long upload in
the middle of a 60-second beacon inflates the mean and can hide C2.
A gap counts as regular if it is within ±10% of the median; 80% of
gaps must match and at least six SYNs are required.

**Internal vs external.** `ipaddress.is_private` treats RFC 5737
documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`) as private. Lab “external” hosts would then look
internal and exfil would never fire. Internal is RFC 1918 IPv4 plus
IPv6 ULA `fc00::/7`, link-local `fe80::/10`, and `::1`. IPv4-mapped
IPv6 (`::ffff:10.0.0.1`) follows the embedded IPv4 rules. `%zone`
suffixes are ignored. `2001:db8::/32` stays external.

**TLS SNI is context, not a finding.** ClientHello is parsed without
decrypting. Every visited HTTPS host would otherwise become an IOC
and a clean capture would report “1 findings (INFO)”. SNI appears on
the timeline as INFO and in a dedicated report section.

**INFO is not scored.** `summarize_findings` drops INFO rows so the
executive line stays “No suspicious activity…” on clean HTTPS.

**DNS.** Long + high-entropy labels (default 40 chars, 3.5 bits/char)
flag tunnelling; optional base32 decode is a lab convenience. The DNS
module adds NXDOMAIN bursts (15 in 10s), a simple DGA score (**20**
unique labels, length 12, entropy 3.5 — raised after a software-update
CDN false-positive), odd mid-length labels, and many unique subdomains
of one base (**16** names, first label ≥ 24).

**HTTP.** Scripted User-Agents (`curl`, `wget`, `python-requests`, …)
are LOW. Suspicious paths (`.exe` / `.ps1`, `/admin`, `cmd=`) are
MEDIUM. Notable non-executable downloads get a SHA-256. MZ/ELF stays
a single CRITICAL finding so it is not reported twice.

**Scans.** Vertical: ≥50 distinct SYN dports in 60s. SYN-scan: ≥20
SYN-only probes with few completed handshakes (half-open / `-sS`).
Horizontal: ≥15 hosts and ≤3 ports, **unless** those ports are only
80/443/8080/8443 *and* handshakes complete (ordinary browsing / streaming).

**Exfil.** One internal→external TCP stream ≥100 KiB.

**FTP.** `USER`/`PASS` on port 21; the password is masked in the report.

## Parser hardening (exam traps)

| Hostile input | Response |
|---------------|----------|
| PCAPng block length ≫ file | Reject; do not allocate |
| `orig_len` / `wirelen` huge, snaplen small | Limit by captured bytes |
| TCP retransmit storm | Dedupe by seq |
| `Content-Length: 999…` or a 40-digit string | Cap / ignore; never `int()` a huge digit string blindly |
| `tcpdump -i any` | SLL / SLL2 headers |
| Tiny TLS handshake records forever | Walk at most 32 records |
| Seeded mutate/truncate fuzz | Fail closed; no hang / no giant alloc |

## Thresholds and profiles

Built-in defaults live in `pcaplens.thresholds` and
`profiles/default.yaml` (they must match). `--profile` overlays a
subset via `yaml.safe_load` only. Unknown keys, wrong types, empty
files, and zero/negative counts raise `invalid profile …`. Module-local
cut-offs (DGA, SYN-scan, NXDOMAIN) were left out of YAML so older
profiles keep loading.

## Custody and ethics

The custody log is a hash chain: each entry includes the hash of the
previous line. `verify-custody` walks the file. Work on a **copy**.
Only analyse traffic you are authorised to examine (UK: Computer Misuse Act 1990).
Do not commit customer PCAPs or credentials.

## CLI exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Missing file or unexpected failure |
| 2 | Usage error, or empty / malformed / unreadable PCAP |
| 130 | Interrupted |

`pcaplens --help` lists the same table plus copy-paste examples.

## Likely extra viva questions

**Why not keep every Scapy packet?** A 1M-frame capture would be
gigabytes of dissected objects. Ingest streams the file, stores compact
facts, and drops each frame. Memory stays bounded by limits, not by
file size.

**Why did DGA / horizontal scan get stricter?** A Windows-Update CDN
mints many unique high-entropy names; a video client talks to many
hosts on 443. Those are not C2 or a port scan. Thresholds are
documented in `dns_analysis.py` / `scan.py` and tested with benign
fixtures.

**How do you know the JSON will not drift?** `validate_json_report`
runs before `report.json` is written. Schema 1.0 keys are required;
unknown keys fail.

## What it does not detect (honest answers)

The full list is [docs/limitations.md](limitations.md). Short version
you can say out loud:

**“Will this catch HTTPS malware?”** Only if it also reconnects on a
regular interval (beacon rule) or you already care about the SNI.
Payloads stay opaque. Encrypted Client Hello yields no hostname.
JA3/JA4 is still a roadmap item.

**“Will a Windows Update look like DGA or a scan?”** The software-update
and streaming fixtures stay clean: DGA needs 20 unique high-entropy
labels; horizontal scan skips completed 80/443 browsing. A noisier CDN
can still trip DGA. That is a known false-positive case, not a surprise.

**“Can a slow scan hide?”** Yes. Fewer than 50 SYN dports in 60s, or a
connect-scan with more than 20% completed handshakes, will not fire.
UDP and ICMP scans are out of scope.

**“What about DoH, HTTP/2, QUIC, VLAN, GRE?”** Not parsed. DoH looks
like HTTPS. HTTP/2 and QUIC downloads will not produce an
executable-download finding. VLAN-tagged and tunneled frames may never
expose the inner IP.

**“Is a clean report a clean network?”** No. It means no current rule
fired. Thresholds, stream caps (8 MiB), and the 250 000-packet default
all hide traffic. Findings are leads.

## What I would say if asked “is this production-ready?”

It is sized for lab / teaching captures and a viva. Production networks
need a clean baseline (software updaters look like beacons). TLS
payloads stay opaque (SNI only; JA3/JA4 is still a roadmap item).
TCP reassembly is a seq map, not a full stream engine. It does not
detect HTTP/2, QUIC, DoH/DoT, VLAN inner frames, or encrypted C2
payloads — see [docs/limitations.md](limitations.md). Findings are
hypotheses for an analyst, not automatic containment.
