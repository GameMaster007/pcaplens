"""Command-line interface for pcaplens."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pcaplens import __version__
from pcaplens.analyze import analyze_pcap
from pcaplens.custody import verify as verify_custody
from pcaplens.parse import PcapParseError
from pcaplens.synth import build_attack_pcap, build_clean_pcap


def cmd_analyse(args: argparse.Namespace) -> int:
    result = analyze_pcap(
        args.pcap,
        case_id=args.case_id,
        examiner=args.examiner,
        out=args.out,
        tshark_cross_check=not args.no_tshark,
    )
    print(
        f"{result.packets} packets, {len(result.findings)} findings, "
        f"{len(result.iocs)} IOCs -> {result.report_path}"
    )
    if result.cross_check:
        print(result.cross_check)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    ok, msg = verify_custody(args.log)
    print(("OK: " if ok else "TAMPERED: ") + msg)
    return 0 if ok else 1


def cmd_gen_sample(args: argparse.Namespace) -> int:
    path = Path(args.out)
    if args.clean:
        build_clean_pcap(path)
        print(f"wrote clean sample PCAP to {path}")
    else:
        build_attack_pcap(path)
        print(f"wrote attack-scenario sample PCAP to {path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pcaplens",
        description=(
            "Offline PCAP triage for SOC / DFIR: beaconing, DNS tunnelling, "
            "port scans, executable downloads, exfiltration, cleartext FTP."
        ),
    )
    p.add_argument("--version", action="version", version=f"pcaplens {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyse", aliases=["analyze"], help="Analyse a PCAP file")
    a.add_argument("pcap", type=Path, help="Path to .pcap / .pcapng")
    a.add_argument("--case-id", default="CASE-001", help="Case identifier for the report")
    a.add_argument("--examiner", default=None, help="Examiner name for custody log")
    a.add_argument("--out", type=Path, default=Path("output"), help="Output directory")
    a.add_argument(
        "--no-tshark",
        action="store_true",
        help="Skip optional tshark HTTP-object cross-check",
    )
    a.set_defaults(func=cmd_analyse)

    v = sub.add_parser("verify-custody", help="Verify a chain-of-custody JSONL log")
    v.add_argument("log", type=Path, help="Path to chain_of_custody.jsonl")
    v.set_defaults(func=cmd_verify)

    g = sub.add_parser("gen-sample", help="Generate a synthetic sample PCAP")
    g.add_argument(
        "--out",
        type=Path,
        default=Path("samples/office_lan.pcap"),
        help="Output PCAP path",
    )
    g.add_argument(
        "--clean",
        action="store_true",
        help="Generate benign traffic only (no findings expected)",
    )
    g.set_defaults(func=cmd_gen_sample)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except PcapParseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130
    except Exception as exc:
        # Last-resort: never dump a traceback to an analyst terminal.
        print(f"error: unexpected failure: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
