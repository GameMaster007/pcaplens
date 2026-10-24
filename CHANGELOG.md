# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `is_internal` now covers IPv4 RFC 1918 and IPv6 RFC 4193 ULA (`fc00::/7`),
  link-local (`fe80::/10`), and loopback (`::1`). RFC 5737 / `2001:db8::/32`
  documentation addresses stay external. Dual-stack synthetic capture in tests.

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
