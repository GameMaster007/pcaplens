"""Versioned JSON report contract (schema_version 1.0). No extra dependency."""
from __future__ import annotations

from typing import Any

JSON_SCHEMA_VERSION = "1.0"
_FINDING_SEV = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})
_ROOT_KEYS = ("schema_version", "case_id", "findings", "iocs", "custody")
_FINDING_KEYS = ("severity", "title", "detail")
_IOC_KEYS = ("type", "value", "context")
_CUSTODY_KEYS = ("summary", "intact", "entries", "pcap_unchanged", "sha256")


class JsonSchemaError(ValueError):
    """Raised when a JSON report does not match schema 1.0."""


def validate_json_report(data: Any) -> None:
    """Raise JsonSchemaError if *data* is not a schema 1.0 report object."""
    if not isinstance(data, dict):
        raise JsonSchemaError("report must be an object")
    missing = [k for k in _ROOT_KEYS if k not in data]
    if missing:
        raise JsonSchemaError(f"missing keys: {', '.join(missing)}")
    extra = sorted(set(data) - set(_ROOT_KEYS))
    if extra:
        raise JsonSchemaError(f"unknown keys: {', '.join(extra)}")
    if data["schema_version"] != JSON_SCHEMA_VERSION:
        raise JsonSchemaError(
            f"schema_version must be {JSON_SCHEMA_VERSION!r}, "
            f"got {data['schema_version']!r}"
        )
    if not isinstance(data["case_id"], str) or not data["case_id"]:
        raise JsonSchemaError("case_id must be a non-empty string")
    _check_findings(data["findings"])
    _check_iocs(data["iocs"])
    _check_custody(data["custody"])


def _check_findings(rows: Any) -> None:
    if not isinstance(rows, list):
        raise JsonSchemaError("findings must be an array")
    for i, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != set(_FINDING_KEYS):
            raise JsonSchemaError(f"findings[{i}] must have {', '.join(_FINDING_KEYS)}")
        if row["severity"] not in _FINDING_SEV:
            raise JsonSchemaError(f"findings[{i}].severity is not a known severity")
        if not all(isinstance(row[k], str) for k in _FINDING_KEYS):
            raise JsonSchemaError(f"findings[{i}] fields must be strings")


def _check_iocs(rows: Any) -> None:
    if not isinstance(rows, list):
        raise JsonSchemaError("iocs must be an array")
    for i, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != set(_IOC_KEYS):
            raise JsonSchemaError(f"iocs[{i}] must have {', '.join(_IOC_KEYS)}")
        if not all(isinstance(row[k], str) for k in _IOC_KEYS):
            raise JsonSchemaError(f"iocs[{i}] fields must be strings")


def _check_custody(row: Any) -> None:
    if not isinstance(row, dict) or set(row) != set(_CUSTODY_KEYS):
        raise JsonSchemaError(f"custody must have {', '.join(_CUSTODY_KEYS)}")
    if not isinstance(row["summary"], str) or not row["summary"]:
        raise JsonSchemaError("custody.summary must be a non-empty string")
    if not isinstance(row["intact"], bool) or not isinstance(row["pcap_unchanged"], bool):
        raise JsonSchemaError("custody.intact and pcap_unchanged must be booleans")
    if type(row["entries"]) is not int or row["entries"] < 0:
        raise JsonSchemaError("custody.entries must be a non-negative integer")
    sha = row["sha256"]
    if not isinstance(sha, str) or len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
        raise JsonSchemaError("custody.sha256 must be a 64-char lowercase hex digest")
