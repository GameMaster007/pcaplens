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
