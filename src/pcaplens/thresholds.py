"""Tunable detection thresholds.

These trade false positives against false negatives. Document them in reports
and tune against a clean baseline before production use.

Override them at run time with ``--profile path.yaml`` (see
``profiles/default.yaml``). Built-in defaults stay in this module so a missing
or omitted profile behaves exactly as before.
"""
from __future__ import annotations

from dataclasses import dataclass, fields, replace
from pathlib import Path
from typing import get_type_hints

import yaml

# Built-in defaults. Thresholds() and profiles/default.yaml must match these.
SCAN_PORTS = 50  # distinct destination ports, one source -> one target
SCAN_WINDOW = 60  # seconds
BEACON_MIN_CONNS = 6
BEACON_TOLERANCE = 0.10  # gap matches if within +-10% of median
BEACON_MIN_RATIO = 0.80  # fraction of gaps that must match
DNS_LABEL_LEN = 40
DNS_ENTROPY = 3.5  # Shannon bits/char
EXFIL_BYTES = 100_000  # internal -> external bytes in one TCP stream


class ProfileError(ValueError):
    """Raised when a YAML threshold profile is missing or invalid."""


@dataclass(frozen=True)
class Thresholds:
    """Detection cut-offs used by analyze_pcap.

    Field names are the YAML keys. Omit a key to keep the built-in default.
    """

    SCAN_PORTS: int = SCAN_PORTS
    SCAN_WINDOW: int = SCAN_WINDOW
    BEACON_MIN_CONNS: int = BEACON_MIN_CONNS
    BEACON_TOLERANCE: float = BEACON_TOLERANCE
    BEACON_MIN_RATIO: float = BEACON_MIN_RATIO
    DNS_LABEL_LEN: int = DNS_LABEL_LEN
    DNS_ENTROPY: float = DNS_ENTROPY
    EXFIL_BYTES: int = EXFIL_BYTES


# Resolved after the class body so ``from __future__ import annotations`` is fine.
_FIELD_TYPES = get_type_hints(Thresholds)
_KNOWN_KEYS = {f.name for f in fields(Thresholds)}


def _check_value(key: str, value: object, expected: type) -> int | float:
    """Reject bool (a subclass of int) and other wrong YAML types."""
    if expected is int:
        if type(value) is not int:
            raise ProfileError(f"{key} must be an integer, got {type(value).__name__}")
        return value
    if expected is float:
        # YAML 1 is int; accept it as 1.0 for ratio / entropy fields.
        if type(value) is bool or type(value) not in (int, float):
            raise ProfileError(f"{key} must be a number, got {type(value).__name__}")
        return float(value)
    raise ProfileError(f"{key} has unsupported type {expected!r}")


def load_profile(path: str | Path) -> Thresholds:
    """Load thresholds from YAML via yaml.safe_load (never yaml.load).

    Unknown keys, wrong types, and unreadable / invalid YAML raise ProfileError
    with the file path so the CLI can print one clear message.
    """
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ProfileError(f"cannot read {path}: {exc}") from exc

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ProfileError(f"invalid YAML in {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ProfileError(f"{path}: profile must be a mapping of threshold names to values")

    unknown = sorted(set(data) - _KNOWN_KEYS)
    if unknown:
        raise ProfileError(f"{path}: unknown key(s): {', '.join(str(k) for k in unknown)}")

    updates: dict[str, int | float] = {}
    for key, raw in data.items():
        try:
            updates[str(key)] = _check_value(str(key), raw, _FIELD_TYPES[key])
        except ProfileError as exc:
            raise ProfileError(f"{path}: {exc}") from exc
    return replace(Thresholds(), **updates)
