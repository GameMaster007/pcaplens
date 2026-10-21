"""Tamper-evident chain-of-custody log and evidence hashing.

Each JSONL entry stores the SHA-256 of the previous entry so edits are
detectable. Supports ACPO Principle 3 / ISO/IEC 27037 auditability.
"""
from __future__ import annotations

import getpass
import hashlib
import json
import platform
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CHUNK = 1024 * 1024


def hash_file(path: str | Path) -> dict[str, str]:
    """Return MD5, SHA-1 and SHA-256 of a file (read-only)."""
    hashes = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    with open(path, "rb") as fh:
        while chunk := fh.read(CHUNK):
            for h in hashes.values():
                h.update(chunk)
    return {name: h.hexdigest() for name, h in hashes.items()}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class CustodyLog:
    def __init__(self, path: str | Path, case_id: str, examiner: str | None = None):
        self.path = Path(path)
        self.case_id = case_id
        self.examiner = examiner or getpass.getuser()
        self._last_hash = "0" * 64
        self._seq = 0
        try:
            with open(self.path) as fh:
                for line in fh:
                    entry = json.loads(line)
                    self._last_hash = entry["entry_hash"]
                    self._seq = entry["seq"]
        except FileNotFoundError:
            pass

    def record(self, action: str, **details: Any) -> dict[str, Any]:
        self._seq += 1
        entry: dict[str, Any] = {
            "seq": self._seq,
            "timestamp_utc": utc_now(),
            "case_id": self.case_id,
            "examiner": self.examiner,
            "workstation": (
                f"{socket.gethostname()} ({platform.system()} {platform.release()})"
            ),
            "action": action,
            "details": details,
            "prev_hash": self._last_hash,
        }
        entry["entry_hash"] = hashlib.sha256(
            json.dumps(entry, sort_keys=True).encode()
        ).hexdigest()
        with open(self.path, "a") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
        self._last_hash = entry["entry_hash"]
        return entry


def verify(path: str | Path) -> tuple[bool, str]:
    """Re-walk the hash chain. Returns (ok, message)."""
    prev = "0" * 64
    n = 0
    with open(path) as fh:
        for n, line in enumerate(fh, 1):
            entry = json.loads(line)
            claimed = entry.pop("entry_hash")
            if entry["prev_hash"] != prev:
                return False, f"chain broken at entry {n}: prev_hash mismatch"
            actual = hashlib.sha256(
                json.dumps(entry, sort_keys=True).encode()
            ).hexdigest()
            if actual != claimed:
                return False, f"entry {n} was modified after it was written"
            prev = claimed
    return True, f"chain intact ({n} entries)"
