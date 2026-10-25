# pcaplens

**Offline PCAP triage for SOC and DFIR analysts.**

`pcaplens` turns a packet capture into a prioritised Markdown report, IOC CSV,
event timeline, extracted HTTP objects, and a hash-chained chain-of-custody log.
Every finding is mapped to [MITRE ATT&CK](https://attack.mitre.org/).

```bash
pip install pcaplens          # once published
pcaplens analyse capture.pcap --case-id INC-42 --out ./out
pcaplens analyse capture.pcap --profile profiles/default.yaml --out ./out
```

> **Authorised use only.** Analyse traffic you own or have explicit permission
> to examine. Heuristic findings are leads, not proof of guilt.

## What it detects

| Detection | Signal | ATT&CK |
|-----------|--------|--------|
| C2 beaconing | Regular connection intervals, low jitter (median-based) | T1071.001 |
| DNS tunnelling | Long / high-entropy subdomain labels (+ optional base32 decode) | T1071.004 / T1048 |
| DNS abuse | NXDOMAIN bursts, simple DGA score, odd labels, many unique subdomains | T1071.004 / T1568.002 |
| Port scan | Many distinct SYN dports in a short window | T1046 |
| SYN scan | Many SYN-only probes, few completed handshakes (half-open) | T1046 |
| Horizontal scan | Many hosts, few ports | T1046 |
| HTTP analysis | Scripted User-Agents, suspicious paths, hashed downloads | T1071.001 / T1105 |
| Executable download | MZ/ELF magic in HTTP response body | T1105 |
| Data exfiltration | Large internal→external TCP stream | T1041 |
| Cleartext FTP creds | `USER`/`PASS` on port 21 (password masked in report) | T1552 / T1040 |

TLS SNI hostnames from ClientHello are recorded as informational context
(visited-site metadata). They are **not** findings or IOCs. Also notes
scripted User-Agents (`python-requests`, `curl`, …) as IOCs.

## Quickstart

```bash
# from a clone
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# generate a synthetic demo capture (not committed as a binary)
pcaplens gen-sample --out samples/office_lan.pcap

# analyse it (Markdown report is the default)
pcaplens analyse samples/office_lan.pcap --case-id DEMO-001 --out output --examiner "You"

# Markdown + HTML report of findings, IOCs, and the timeline
pcaplens report samples/office_lan.pcap --case-id DEMO-001 --out output --no-tshark

# same analysis as machine-readable JSON
pcaplens analyse samples/office_lan.pcap --format json --out output-json

# verify the custody log
pcaplens verify-custody output/chain_of_custody.jsonl
```

Optional: install [Wireshark](https://www.wireshark.org/)'s `tshark` for an
independent HTTP-object count cross-check (`--no-tshark` to skip).

## Usage walkthrough

A 5-minute path from clone to a defendable report. Use the synthetic sample
in a viva; do not commit real captures.

1. **Install** (Python 3.10–3.12). Runtime deps are Scapy and PyYAML only.

   ```bash
   python3 -m venv .venv && source .venv/bin/activate
   pip install -e ".[dev]"
   ```

2. **Build a lab PCAP.** `gen-sample` writes RFC 5737 / `.example` traffic
   covering every detection class. `--clean` is the false-positive check.

   ```bash
   pcaplens gen-sample --out samples/office_lan.pcap
   pcaplens gen-sample --clean --out samples/clean.pcap
   ```

3. **Triage.** `analyse` hashes the file, walks packets, writes the report
   plus CSVs, extracted HTTP objects, and a hash-chained custody log.

   ```bash
   pcaplens analyse samples/office_lan.pcap \
     --case-id DEMO-001 --examiner "You" --out output --no-tshark
   ```

4. **Read the report.** Open `output/report.md`. Severity order is
   CRITICAL → HIGH → MEDIUM → LOW. INFO rows (TLS SNI, HTTP requests) are
   timeline context and do **not** count as “findings”. A clean capture
   prints `No suspicious activity detected by the current rules.`

5. **Share HTML or JSON.** `pcaplens report` writes Markdown and/or HTML.
   `analyse --format json` writes the versioned object in
   [docs/json-report.md](docs/json-report.md).

   ```bash
   pcaplens report samples/office_lan.pcap --format both --out output --no-tshark
   pcaplens analyse samples/office_lan.pcap --format json --out output-json
   ```

6. **Tune, then re-run.** Copy `profiles/default.yaml`, change one
   threshold, pass `--profile lab.yaml`. Unknown keys and non-positive
   counts are rejected (`yaml.safe_load` only).

7. **Prove the file did not change.**

   ```bash
   pcaplens verify-custody output/chain_of_custody.jsonl
   ```

Why a finding fired, why SNI is not an IOC, and how the parser fails closed
are answered in [docs/viva.md](docs/viva.md).

## Example output

```text
790 packets, 6 findings, 7 IOCs -> output/report.md
tshark --export-objects found 21 HTTP objects; this tool extracted 21
```

`output/report.md` includes an executive summary, severity-ranked findings,
ATT&CK-mapped timeline, IOC table, and top talkers. With `--format json` the
report is `output/report.json` instead (see [JSON report](#json-report)).
Also written:

- `events.csv` — full timeline  
- `iocs.csv` — indicators  
- `extracted_objects/` — HTTP bodies + `objects.sha256`  
- `chain_of_custody.jsonl` — tamper-evident audit log  

## How detections work (thresholds)

Constants live in `pcaplens.thresholds` and are intentionally simple so you can
defend them in a viva or tune them on a clean baseline. Override them with
`--profile lab.yaml` (see `profiles/default.yaml` for the built-in values).
Unknown keys, wrong types, empty files, and zero/negative counts are rejected:

| Constant | Default | Meaning |
|----------|---------|---------|
| `SCAN_PORTS` / `SCAN_WINDOW` | 50 / 60s | Distinct SYN dports within window |
| `BEACON_MIN_CONNS` | 6 | Minimum SYNs before judging regularity |
| `BEACON_TOLERANCE` / `BEACON_MIN_RATIO` | 10% / 80% | Gaps within ±10% of median |
| `DNS_LABEL_LEN` / `DNS_ENTROPY` | 40 / 3.5 | Long + high-entropy label |
| `EXFIL_BYTES` | 100_000 | Internal→external stream size |

Beaconing uses a **median** gap test so one long upload does not hide an
otherwise metronomic beacon (a plain stdev/mean test would).

## JSON report

`pcaplens analyse capture.pcap --format json --out ./out` writes
`out/report.json`. The schema is versioned (`schema_version`, currently
`"1.0"`) and documented in [docs/json-report.md](docs/json-report.md).

```json
{
  "schema_version": "1.0",
  "case_id": "INC-42",
  "findings": [
    {"severity": "HIGH", "title": "Port scan", "detail": "..."}
  ],
  "iocs": [
    {"type": "ip", "value": "10.10.0.99", "context": "internal scanning host"}
  ],
  "custody": {
    "summary": "chain intact (4 entries)",
    "intact": true,
    "entries": 4,
    "pcap_unchanged": true,
    "sha256": "..."
  }
}
```

## Library API

```python
from pcaplens import analyze_pcap, load_profile

# built-in defaults
result = analyze_pcap("capture.pcap", case_id="INC-1", out="out")
# or override from a YAML profile
result = analyze_pcap(
    "capture.pcap",
    thresholds=load_profile("lab.yaml"),
    out="out",
)
print(len(result.findings), result.sha256)

result = analyze_pcap("capture.pcap", out="out-json", report_format="json")
```

## Limitations

- Tuned for lab / teaching captures; production networks need baselining
  (software updaters also “beacon”).
- TLS payloads stay opaque; SNI is read from ClientHello (JA3/JA4 still on the roadmap).
- Internal hosts are RFC 1918 IPv4 (including IPv4-mapped IPv6) and IPv6
  ULA / link-local / loopback; documentation prefixes (RFC 5737,
  `2001:db8::/32`) count as external.
- TCP reassembly is best-effort (seq map; retransmits are ignored); not a
  full Wireshark replacement.
- Not an accredited forensic method under the UK Forensic Science Regulator Code.

## Ethics & legal

- Only analyse captures you are **authorised** to examine (owner consent,
  employer policy, warrant). In the UK see the Computer Misuse Act 1990.
- Prefer working on a **copy**; pcaplens hashes the file before and after.
- Do not commit real customer PCAPs or credentials to git.

## Roadmap / good first issues

See [docs/ROADMAP.md](docs/ROADMAP.md). Friendly starter tasks:

1. Add JA3/JA4 fingerprints from TLS ClientHello (SNI is already extracted).  
2. Emit findings as Sigma-like YAML or a tiny Suricata rule stub.  
3. HTML report theme (keep Markdown as default).  
4. Progress bar / packet count for large PCAPs.  

## Development

```bash
pip install -e ".[dev]"
pytest -q
ruff check src tests scripts
```

CI runs ruff + pytest on Python 3.10–3.12 (see `.github/workflows/ci.yml`).

## License

[MIT](LICENSE) © Benjamin Christy
