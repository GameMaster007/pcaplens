#!/usr/bin/env python3
"""Generate the demo PCAP used in README examples (not committed as a binary)."""
from __future__ import annotations

import argparse
from pathlib import Path

from pcaplens.synth import build_attack_pcap, build_clean_pcap


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--out", type=Path, default=Path("samples/office_lan.pcap"))
    p.add_argument("--clean", action="store_true")
    args = p.parse_args()
    path = build_clean_pcap(args.out) if args.clean else build_attack_pcap(args.out)
    print(f"wrote {path} ({path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
