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
3. **Reassemble TCP** by sequence number. Retransmits share a seq and
   do not spend the stream-size budget.
4. **Detect.** Independent modules (scan, DNS, HTTP, beacon, exfil,
   FTP, TLS SNI) append findings / events / IOCs.
5. **Write.** Markdown or JSON report, `events.csv`, `iocs.csv`,
   `extracted_objects/`, `chain_of_custody.jsonl`. Pre- and post-hash
   of the PCAP must match.

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
module adds NXDOMAIN bursts, a simple DGA score (many unique
high-entropy labels), odd mid-length labels, and many unique
subdomains of one base.

**HTTP.** Scripted User-Agents (`curl`, `wget`, `python-requests`, …)
are LOW. Suspicious paths (`.exe` / `.ps1`, `/admin`, `cmd=`) are
MEDIUM. Notable non-executable downloads get a SHA-256. MZ/ELF stays
a single CRITICAL finding so it is not reported twice.

**Scans.** Vertical: ≥50 distinct SYN dports in 60s. SYN-scan: ≥20
SYN-only probes with few completed handshakes (half-open / `-sS`).
Horizontal: ≥15 hosts and ≤3 ports.

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

## What I would say if asked “is this production-ready?”

It is sized for lab / teaching captures and a viva. Production networks
need a clean baseline (software updaters look like beacons). TLS
payloads stay opaque (SNI only; JA3/JA4 is still a roadmap item).
TCP reassembly is a seq map, not a full stream engine. Findings are
hypotheses for an analyst, not automatic containment.
