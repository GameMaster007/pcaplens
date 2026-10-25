"""Tunable detection thresholds.

These trade false positives against false negatives. Document them in reports
and tune against a clean baseline before production use.

Override them at run time with ``--profile path.yaml`` (see
``profiles/default.yaml``). Built-in defaults stay in this module so omitting
``--profile`` behaves exactly as before.
"""
from __future__ import annotations

import math
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

    YAML keys are these field names (SCAN_PORTS, EXFIL_BYTES, ...).
    Omit a key to keep the built-in default.
    """

    SCAN_PORTS: int = SCAN_PORTS
    SCAN_WINDOW: int = SCAN_WINDOW
    BEACON_MIN_CONNS: int = BEACON_MIN_CONNS
    BEACON_TOLERANCE: float = BEACON_TOLERANCE
    BEACON_MIN_RATIO: float = BEACON_MIN_RATIO
    DNS_LABEL_LEN: int = DNS_LABEL_LEN
    DNS_ENTROPY: float = DNS_ENTROPY
    EXFIL_BYTES: int = EXFIL_BYTES


# Looked up after the class so ``from __future__ import annotations`` is fine.
_FIELD_TYPES = get_type_hints(Thresholds)
_KNOWN_KEYS = {f.name for f in fields(Thresholds)}


def _invalid(path: Path, message: str) -> ProfileError:
    """One wording for every profile failure so the CLI stays predictable."""
    return ProfileError(f"invalid profile {path}: {message}")


def _check_value(key: str, value: object, expected: type) -> int | float:
    """Check YAML types and obvious out-of-range numbers.

    ``bool`` is a subclass of ``int`` in Python, so ``SCAN_PORTS: true``
    would otherwise sneak through as 1. Reject it.
    """
    if value is None:
        raise ProfileError(f"{key} must not be null")

    if expected is int:
        if type(value) is not int:
            raise ProfileError(f"{key} must be an integer, got {type(value).__name__}")
        # Two SYNs are required before a gap (and therefore a median) exists.
        if key == "BEACON_MIN_CONNS" and value < 2:
            raise ProfileError(
                f"{key} must be at least 2 (need two connections to measure a gap), got {value}"
            )
        if value < 1:
            raise ProfileError(f"{key} must be greater than 0, got {value}")
        return value

    if expected is float:
        # YAML 1 is int; accept it as 1.0 for ratio / entropy fields.
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ProfileError(f"{key} must be a number, got {type(value).__name__}")
        number = float(value)
        if not math.isfinite(number):
            raise ProfileError(f"{key} must be a finite number, got {value}")
        if number < 0:
            raise ProfileError(f"{key} must be 0 or greater, got {value}")
        if key == "BEACON_MIN_RATIO" and number > 1:
            raise ProfileError(f"{key} must be between 0 and 1, got {value}")
        return number

    raise ProfileError(f"{key} has unsupported type {expected!r}")


def load_profile(path: str | Path) -> Thresholds:
    """Load thresholds from YAML via yaml.safe_load (never yaml.load).

    Steps: read the file, parse YAML, reject unknown keys / bad types /
    out-of-range numbers, then overlay the rest onto the built-in defaults.
    """
    path = Path(path)

    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise _invalid(path, "file not found") from None
    except IsADirectoryError:
        raise _invalid(path, "is a directory, not a file") from None
    except UnicodeDecodeError:
        raise _invalid(path, "not valid UTF-8") from None
    except OSError as exc:
        raise _invalid(path, f"cannot read file ({exc})") from exc

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        # First line only: the full PyYAML dump is noisy for a CLI error.
        detail = str(exc).strip().splitlines()[0].rstrip(":")
        raise _invalid(path, f"invalid YAML ({detail})") from exc

    # Empty files, comment-only files, and a lone ``null`` all parse as None.
    if data is None:
        raise _invalid(path, "file is empty (expected a mapping of threshold names to values)")
    if not isinstance(data, dict):
        raise _invalid(
            path,
            f"must be a mapping of threshold names to values, got {type(data).__name__}",
        )

    unknown = sorted(set(data) - _KNOWN_KEYS, key=str)
    if unknown:
        raise _invalid(path, f"unknown key(s): {', '.join(str(k) for k in unknown)}")

    updates: dict[str, int | float] = {}
    for key, raw in data.items():
        name = str(key)
        try:
            updates[name] = _check_value(name, raw, _FIELD_TYPES[key])
        except ProfileError as exc:
            raise _invalid(path, str(exc)) from exc
    return replace(Thresholds(), **updates)  # type: ignore[arg-type]
