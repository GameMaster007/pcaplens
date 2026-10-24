# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Email a private report to the maintainer via GitHub Security Advisories on
https://github.com/GameMaster007/pcaplens (Security → Report a vulnerability),
or open a draft advisory.

Include:
- pcaplens version
- steps to reproduce
- impact assessment

You should receive an acknowledgement within 7 days.

## Scope notes

pcaplens analyses packet captures **offline**. It does not open network sockets
to fetch threat intel by default. Findings are heuristic indicators, not proof
of compromise. Only analyse captures you are authorised to examine.

## Untrusted PCAPs

Treat every capture as untrusted input. A `.pcap` / `.pcapng` file is a
length-prefixed binary format: lying `incl_len` values, truncated records,
and malformed DNS or HTTP payloads are a real attack surface (memory
exhaustion, long loops, unexpected exceptions).

pcaplens therefore:

- **Streams** packets from disk instead of loading the whole file via
  `rdpcap`. Classic PCAP records are parsed by hand so a 2 GiB `incl_len`
  is rejected before any corresponding read.
- **Bounds memory** with `ParseLimits` (file size, packet count, captured
  packet size, reassembled TCP stream size, HTTP header/body size, DNS
  name length). Defaults live in `pcaplens.parse.ParseLimits` and can be
  passed into `analyze_pcap(..., limits=...)`.
- **Fails closed** on a structural problem (bad magic, truncated header,
  empty file, limit breach). The CLI prints `error: ...` to stderr and
  exits non-zero — it does not crash or hang.
- **Skips** individual frames whose DNS/HTTP payload is garbage, rather
  than aborting the rest of a readable capture.

Do not raise the limits to “unlimited” on captures from an unknown
source. Prefer working on a **copy**; pcaplens hashes the file before and
after analysis but will not protect you from a hostile file that is
designed only to crash the process.
