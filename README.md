# pcaplens

**Offline PCAP triage for SOC and DFIR analysts.**

`pcaplens` turns a packet capture into a prioritised Markdown report, IOC CSV,
event timeline, extracted HTTP objects, and a hash-chained chain-of-custody log.
Every finding is mapped to [MITRE ATT&CK](https://attack.mitre.org/).

```bash
pip install pcaplens          # once published
pcaplens analyse capture.pcap --case-id INC-42 --out ./out
```

> **Authorised use only.** Analyse traffic you own or have explicit permission
> to examine. Heuristic findings are leads, not proof of guilt.

## What it detects

| Detection | Signal | ATT&CK |
|-----------|--------|--------|
| C2 beaconing | Regular connection intervals, low jitter (median-based) | T1071.001 |
| DNS tunnelling | Long / high-entropy subdomain labels (+ optional base32 decode) | T1071.004 / T1048 |
| Port scan | Many distinct SYN destinations in a short window | T1046 |
| Executable download | MZ/ELF magic in HTTP response body | T1105 |
| Data exfiltration | Large internal→external TCP stream | T1041 |
| Cleartext FTP creds | `USER`/`PASS` on port 21 (password masked in report) | T1552 / T1040 |

Also notes scripted User-Agents (`python-requests`, `curl`, …) as IOCs.

## Quickstart

```bash
# from a clone
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# generate a synthetic demo capture (not committed as a binary)
pcaplens gen-sample --out samples/office_lan.pcap

# analyse it (Markdown report is the default)
pcaplens analyse samples/office_lan.pcap --case-id DEMO-001 --out output --examiner "You"

# same analysis as machine-readable JSON
pcaplens analyse samples/office_lan.pcap --format json --out output-json

# verify the custody log
pcaplens verify-custody output/chain_of_custody.jsonl
```

Optional: install [Wireshark](https://www.wireshark.org/)'s `tshark` for an
independent HTTP-object count cross-check (`--no-tshark` to skip).

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
defend them in a viva or tune them on a clean baseline:

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
from pcaplens import analyze_pcap

result = analyze_pcap("capture.pcap", case_id="INC-1", out="out")
print(len(result.findings), result.sha256)
```

## Limitations

- Tuned for lab / teaching captures; production networks need baselining
  (software updaters also “beacon”).
- TLS payloads are opaque — use SNI / JA3 / cert / flow metadata (roadmap).
- TCP reassembly is best-effort (seq map); not a full Wireshark replacement.
- Not an accredited forensic method under the UK Forensic Science Regulator Code.

## Ethics & legal

- Only analyse captures you are **authorised** to examine (owner consent,
  employer policy, warrant). In the UK see the Computer Misuse Act 1990.
- Prefer working on a **copy**; pcaplens hashes the file before and after.
- Do not commit real customer PCAPs or credentials to git.

## Roadmap / good first issues

See [docs/ROADMAP.md](docs/ROADMAP.md). Friendly starter tasks:

1. Add JA3/SNI extraction for TLS ClientHello (no decryption).  
2. Emit findings as Sigma-like YAML or a tiny Suricata rule stub.  
3. HTML report theme (keep Markdown as default).  
4. IPv6 support in the internal/external classifier.  
5. Progress bar / packet count for large PCAPs.  

## Development

```bash
pip install -e ".[dev]"
pytest -q
ruff check src tests scripts
```

CI runs ruff + pytest on Python 3.10–3.12 (see `.github/workflows/ci.yml`).

## License

[MIT](LICENSE) © Benjamin Christy
