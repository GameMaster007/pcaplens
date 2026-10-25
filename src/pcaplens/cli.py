"""Command-line interface for pcaplens."""
from __future__ import annotations

import argparse
import sys
import textwrap
from dataclasses import replace
from pathlib import Path

from pcaplens import __version__
from pcaplens.analyze import REPORT_FORMATS, AnalysisResult, analyze_pcap
from pcaplens.custody import verify as verify_custody
from pcaplens.parse import DEFAULT_LIMITS, ParseLimits, PcapParseError
from pcaplens.report import REPORT_KINDS, write_reports
from pcaplens.synth import build_attack_pcap, build_clean_pcap
from pcaplens.thresholds import ProfileError, Thresholds, load_profile


def _profile_arg(value: str) -> Thresholds:
    """argparse type: turn --profile PATH into Thresholds, or a clear CLI error."""
    try:
        return load_profile(value)
    except ProfileError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _positive_int(value: str) -> int:
    """argparse type: --max-packets / --max-file-bytes must be >= 1.

    ``0`` used to be treated as "use the default" because the old
    truthiness check skipped it. A zero cap is a usage error.
    """
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"must be a positive integer, not {value!r}"
        ) from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError(f"must be a positive integer, not {parsed}")
    return parsed


def _limits_from_args(args: argparse.Namespace) -> ParseLimits:
    limits = DEFAULT_LIMITS
    if args.max_packets is not None:
        limits = replace(limits, max_packets=args.max_packets)
    if args.max_file_bytes is not None:
        limits = replace(limits, max_file_bytes=args.max_file_bytes)
    return limits


def _count_word(n: int, singular: str, plural: str | None = None) -> str:
    if n == 1:
        return singular
    return plural if plural is not None else f"{singular}s"


def _add_shared_triage_args(parser: argparse.ArgumentParser) -> None:
    """Flags shared by analyse and report so the two commands stay in sync."""
    parser.add_argument("pcap", type=Path, help="Path to .pcap / .pcapng")
    parser.add_argument("--case-id", default="CASE-001", help="Case identifier for the report")
    parser.add_argument("--examiner", default=None, help="Examiner name for custody log")
    parser.add_argument("--out", type=Path, default=Path("output"), help="Output directory")
    parser.add_argument(
        "--no-tshark",
        action="store_true",
        help="Skip optional tshark HTTP-object cross-check",
    )
    parser.add_argument(
        "--profile",
        dest="thresholds",
        type=_profile_arg,
        default=None,
        metavar="PATH",
        help=(
            "YAML file of detection thresholds "
            "(built-in defaults if omitted; see profiles/default.yaml)"
        ),
    )
    parser.add_argument(
        "--max-packets",
        type=_positive_int,
        default=None,
        metavar="N",
        help=f"Refuse captures with more than N packets (default {DEFAULT_LIMITS.max_packets:,})",
    )
    parser.add_argument(
        "--max-file-bytes",
        type=_positive_int,
        default=None,
        metavar="N",
        help=f"Refuse captures larger than N bytes (default {DEFAULT_LIMITS.max_file_bytes:,})",
    )


def _try_analyze(
    args: argparse.Namespace,
    *,
    report_format: str = "markdown",
    emit_report: bool = True,
) -> tuple[AnalysisResult | None, int]:
    """Shared analyse/report path so exit codes stay identical."""
    try:
        result = analyze_pcap(
            args.pcap,
            case_id=args.case_id,
            examiner=args.examiner,
            out=args.out,
            tshark_cross_check=not args.no_tshark,
            thresholds=args.thresholds,
            limits=_limits_from_args(args),
            report_format=report_format,
            emit_report=emit_report,
        )
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return None, 1
    except PcapParseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return None, 2
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return None, 1
    return result, 0


def cmd_analyse(args: argparse.Namespace) -> int:
    result, rc = _try_analyze(args, report_format=args.report_format)
    if result is None:
        return rc
    dest = result.report_path if result.report_path is not None else args.out
    print(
        f"{result.packets} {_count_word(result.packets, 'packet')}, "
        f"{len(result.findings)} {_count_word(len(result.findings), 'finding')}, "
        f"{len(result.iocs)} {_count_word(len(result.iocs), 'IOC')} -> {dest}"
    )
    if result.cross_check:
        print(result.cross_check)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    ok, msg = verify_custody(args.log)
    print(("OK: " if ok else "TAMPERED: ") + msg)
    return 0 if ok else 1


def cmd_report(args: argparse.Namespace) -> int:
    """Analyse a PCAP and write Markdown and/or HTML reports."""
    # emit_report=False so --format html does not also write report.md.
    result, rc = _try_analyze(args, emit_report=False)
    if result is None:
        return rc
    if result.report_data is None:
        print("error: analysis produced no report data", file=sys.stderr)
        return 1
    written = write_reports(args.out, result.report_data, args.report_kind)
    names = ", ".join(str(path.name) for path in written)
    print(
        f"{result.packets} {_count_word(result.packets, 'packet')}, "
        f"{len(result.findings)} {_count_word(len(result.findings), 'finding')}, "
        f"{len(result.iocs)} {_count_word(len(result.iocs), 'IOC')} -> {names}"
    )
    return 0


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
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Offline PCAP triage for SOC / DFIR: beaconing, DNS tunnelling, "
            "port scans, executable downloads, exfiltration, cleartext FTP."
        ),
        epilog=textwrap.dedent(
            """\
            examples:
              pcaplens analyse capture.pcap --case-id INC-42 --out ./out --no-tshark
              pcaplens analyse capture.pcap --format json --profile profiles/default.yaml
              pcaplens report capture.pcap --format html --out ./out
              pcaplens verify-custody out/chain_of_custody.jsonl
              pcaplens gen-sample --clean --out samples/clean.pcap

            exit codes:
              0   success
              1   missing file or unexpected failure
              2   usage error, or empty/malformed/unreadable PCAP
              130 interrupted
            """
        ),
    )
    p.add_argument("--version", action="version", version=f"pcaplens {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyse", aliases=["analyze"], help="Analyse a PCAP file")
    _add_shared_triage_args(a)
    # dest avoids clobbering the builtin name `format`.
    # analyse --format is markdown|json; report --format is markdown|html|both.
    a.add_argument(
        "--format",
        dest="report_format",
        choices=REPORT_FORMATS,
        default="markdown",
        help=(
            "analyse output: markdown (report.md, default) or json (report.json). "
            "Different from `report --format` (markdown / html / both)"
        ),
    )
    a.set_defaults(func=cmd_analyse)

    r = sub.add_parser(
        "report",
        help="Write Markdown and/or HTML reports of findings, IOCs, and timeline",
    )
    _add_shared_triage_args(r)
    r.add_argument(
        "--format",
        dest="report_kind",
        choices=REPORT_KINDS,
        default="both",
        help=(
            "report files: markdown (report.md), html (report.html), or both "
            "(default). Different from `analyse --format` (markdown / json)"
        ),
    )
    r.set_defaults(func=cmd_report)

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
