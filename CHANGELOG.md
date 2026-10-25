# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- Stream PCAPs and enforce size/count limits so malformed or huge captures
  fail closed (clear CLI error, non-zero exit) instead of crashing or hanging.
- Harden DNS/HTTP/TCP-reassembly parsers against bogus lengths; add a
  synthetic malformed-PCAP corpus and a small fuzz-style test.
- Validate PCAPng block Total Length against remaining file bytes (a 120-byte
  file that claims a 2.1 GiB block is rejected without allocating).
- Packet-size limits use captured length, not on-wire `orig_len` / `wirelen`.
- TCP reassembly counts unique sequence numbers only, so retransmits do not
  exhaust the stream-size cap.
- Decode Linux cooked captures (`LINKTYPE_LINUX_SLL` / `SLL2`, `tcpdump -i any`)
  and DLT_RAW IPv6.

### Added
- `is_internal` now covers IPv4 RFC 1918 and IPv6 RFC 4193 ULA (`fc00::/7`),
  link-local (`fe80::/10`), and loopback (`::1`). RFC 5737 / `2001:db8::/32`
  documentation addresses stay external. IPv4-mapped IPv6 (`::ffff:10.0.0.1`)
  follows the embedded IPv4 rules; `%zone` suffixes are ignored. Dual-stack
  synthetic capture in tests.
- `--profile path.yaml` loads detection thresholds (scan, beacon, DNS, exfil)
  from a YAML file. Built-in defaults are unchanged; `profiles/default.yaml`
  matches them exactly. Unknown keys, wrong types, empty/null files, missing
  paths, nested mappings, and zero/negative counts raise a clear
  `invalid profile …` error. Parsing uses `yaml.safe_load` only.
- `pcaplens analyse --format json` writes findings, IOCs, and a custody
  summary as versioned JSON (`schema_version`). Markdown remains the default.
- TLS ClientHello SNI extraction per flow (no decryption). Hostnames are
  informational context only — not findings or IOCs. JA3/JA4 remain out of scope.

## [0.1.0] - 2026-10-21

### Added
- Initial public release of **pcaplens**.
- Detections: C2 beaconing, DNS tunnelling, port scans, HTTP executable downloads,
  large outbound transfers, cleartext FTP credentials (MITRE ATT&CK mapped).
- CLI: `pcaplens analyse`, `pcaplens gen-sample`, `pcaplens verify-custody`.
- Hash-chained chain-of-custody JSONL log; pre/post PCAP hashing.
- Synthetic PCAP builders for tests and demos (no large binaries in the repo).
- Optional tshark HTTP-object cross-check.
- pytest suite asserting each detection class and a clean-capture false-positive check.
