# Sample captures

These files are **synthetic**. They use RFC 5737 / RFC 2606 addresses and
names only. Do not add real customer traffic.

Regenerate the committed fixtures:

```bash
python3 scripts/generate_fixtures.py
```

| File | What it is | Expected CLI |
|------|------------|--------------|
| `fixtures/clean_browse.pcap` | Ordinary browsing + HTTPS SNI | exit 0, no findings |
| `fixtures/syn_scan.pcap` | Half-open SYN scan | exit 0, SYN-scan finding |
| `fixtures/truncated.pcap` | Cut-off PCAP header | exit 2 |

Larger demo captures (attack / clean office LAN) are **not** committed.
Build them with `pcaplens gen-sample`.
