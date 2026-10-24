# JSON report schema

`pcaplens analyse --format json` writes `report.json` instead of `report.md`.
Markdown remains the default (`--format markdown`).

The object includes a `schema_version` field. This document describes
**schema version `1.0`**. A new `schema_version` is required for breaking
changes (renamed, removed, or retyped fields). Compatible revisions may add
optional fields without bumping the major version.

CSVs, extracted objects, and `chain_of_custody.jsonl` are still written
alongside the JSON report.

## Root object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schema_version` | string | yes | Schema identifier. `"1.0"` for this document. |
| `case_id` | string | yes | Case identifier from `--case-id`. |
| `findings` | array of finding | yes | Severity-ranked findings (may be empty). |
| `iocs` | array of IOC | yes | Indicators of compromise (may be empty). |
| `custody` | object | yes | Chain-of-custody summary. |

## Finding

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `severity` | string | yes | `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`. |
| `title` | string | yes | Short finding name. |
| `detail` | string | yes | Human-readable detail. |

## IOC

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | yes | Indicator kind (`ip`, `domain`, `url`, `sha256`, `user-agent`, …). |
| `value` | string | yes | Indicator value. |
| `context` | string | yes | Why it was listed. |

## Custody

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `summary` | string | yes | Same message as `pcaplens verify-custody`. |
| `intact` | boolean | yes | Whether the hash chain verified. |
| `entries` | integer | yes | Number of JSONL custody entries. |
| `pcap_unchanged` | boolean | yes | Pre/post analysis hashes match. |
| `sha256` | string | yes | SHA-256 of the capture before analysis. |

## Example

```json
{
  "schema_version": "1.0",
  "case_id": "INC-42",
  "findings": [
    {
      "severity": "HIGH",
      "title": "Likely C2 beaconing",
      "detail": "10.10.0.21 -> 203.0.113.66:443 8 connections, median interval 60.0s"
    }
  ],
  "iocs": [
    {
      "type": "ip",
      "value": "203.0.113.66",
      "context": "beacon destination port 443"
    }
  ],
  "custody": {
    "summary": "chain intact (4 entries)",
    "intact": true,
    "entries": 4,
    "pcap_unchanged": true,
    "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  }
}
```
