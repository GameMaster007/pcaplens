# Roadmap

## 0.2

- [x] TLS ClientHello SNI (no decryption)
- [ ] TLS ClientHello JA3/JA4 fingerprints
- [x] IPv6 + RFC4193 ULA classification
- [x] JSON report export (`--format json`)
- [ ] Progress reporting for multi-GB captures

## 0.3

- [ ] Optional Zeek/Suricata log ingest for correlation
- [x] Configurable threshold profiles (YAML)
- [ ] HTML report

## Good first issues

These are intentionally scoped for new contributors:

| Issue idea | Skills | Notes |
|------------|--------|-------|
| Extract JA3/JA4 from ClientHello | Scapy, TLS | SNI already shipped |
| `--format json` for findings/IOCs | Python, CLI | Keep Markdown default |
| Quieter logging / `-q` flag | CLI UX | |
| Docs: GIF of CLI run | Writing | Synthetic PCAP only |

Open an issue with the **feature request** template before large PRs.
