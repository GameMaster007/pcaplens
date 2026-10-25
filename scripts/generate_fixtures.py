#!/usr/bin/env python3
"""Write the tiny committed sample PCAPs under samples/fixtures/.

No real or private traffic. Re-run after changing synth builders and
commit the result if the files change.
"""
from __future__ import annotations

import struct
from pathlib import Path

from pcaplens.synth import build_clean_pcap, build_syn_scan_pcap

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "samples" / "fixtures"


def _truncated_pcap(path: Path) -> Path:
    """Valid magic plus a cut-off global header — must fail closed."""
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    path.write_bytes(header[:18])
    return path


def main() -> None:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    written = [
        build_clean_pcap(FIXTURES / "clean_browse.pcap"),
        build_syn_scan_pcap(FIXTURES / "syn_scan.pcap"),
        _truncated_pcap(FIXTURES / "truncated.pcap"),
    ]
    for path in written:
        print(f"{path.relative_to(ROOT)} {path.stat().st_size} bytes")


if __name__ == "__main__":
    main()
