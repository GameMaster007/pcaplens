# Roadmap

## 0.2

- [ ] TLS ClientHello metadata (SNI, JA3/JA4) without decryption
- [ ] IPv6 + RFC4193 ULA classification
- [ ] JSON report export (`--format json`)
- [ ] Progress reporting for multi-GB captures

## 0.3

- [ ] Optional Zeek/Suricata log ingest for correlation
- [ ] Configurable threshold profiles (YAML)
- [ ] HTML report

## Good first issues

These are intentionally scoped for new contributors:

| Issue idea | Skills | Notes |
|------------|--------|-------|
| Extract TLS SNI from ClientHello | Scapy, TLS | No payload decrypt |
| `--format json` for findings/IOCs | Python, CLI | Keep Markdown default |
| IPv6 `is_internal` helper | Networking | Dual-stack tests |
| Quieter logging / `-q` flag | CLI UX | |
| Docs: GIF of CLI run | Writing | Synthetic PCAP only |

Open an issue with the **feature request** template before large PRs.
