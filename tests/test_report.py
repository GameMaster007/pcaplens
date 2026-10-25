"""pcaplens report: Markdown/HTML findings, IOCs, and timeline."""
from __future__ import annotations

from pathlib import Path

import pytest

from pcaplens.cli import main
from pcaplens.report import ReportData, render_html, render_markdown
from pcaplens.synth import build_attack_pcap, build_clean_pcap


def test_cli_report_writes_markdown_and_html(tmp_path: Path):
    pcap = build_attack_pcap(tmp_path / "a.pcap")
    out = tmp_path / "rep"
    rc = main(
        [
            "report",
            str(pcap),
            "--case-id",
            "REP-1",
            "--out",
            str(out),
            "--no-tshark",
        ]
    )
    assert rc == 0
    md = out / "report.md"
    html = out / "report.html"
    assert md.is_file() and html.is_file()
    text = md.read_text(encoding="utf-8")
    page = html.read_text(encoding="utf-8")
    assert "Network Forensics Report - REP-1" in text
    assert "## Findings" in text
    assert "## Indicators of compromise" in text
    assert "## Timeline (non-informational events)" in text
    assert "Network Forensics Report - REP-1" in page
    assert "<h2>Findings</h2>" in page
    assert "<h2>Indicators of compromise</h2>" in page
    assert "<h2>Timeline (non-informational events)</h2>" in page
    assert "beacon" in text.lower() or "Port scan" in text


def test_cli_report_html_only(tmp_path: Path):
    pcap = build_clean_pcap(tmp_path / "c.pcap")
    out = tmp_path / "html_only"
    rc = main(
        [
            "report",
            str(pcap),
            "--format",
            "html",
            "--out",
            str(out),
            "--no-tshark",
        ]
    )
    assert rc == 0
    assert (out / "report.html").is_file()
    page = (out / "report.html").read_text(encoding="utf-8")
    assert "No suspicious activity detected by the current rules." in page


def test_cli_report_markdown_only_matches_analyse(tmp_path: Path):
    pcap = build_attack_pcap(tmp_path / "a.pcap")
    report_out = tmp_path / "from_report"
    analyse_out = tmp_path / "from_analyse"
    assert main(
        ["report", str(pcap), "--format", "markdown", "--out", str(report_out), "--no-tshark"]
    ) == 0
    assert main(
        ["analyse", str(pcap), "--out", str(analyse_out), "--no-tshark"]
    ) == 0
    assert (report_out / "report.md").read_text(encoding="utf-8") == (
        (analyse_out / "report.md").read_text(encoding="utf-8")
    )
    assert not (report_out / "report.html").exists()


def test_html_escapes_injected_markup():
    data = ReportData(
        case_id="<script>alert(1)</script>",
        pcap_name="x.pcap",
        pcap_bytes=1,
        sha256="ab",
        unchanged=True,
        packets=1,
        t0=0,
        t1=1,
        custody="ok",
        cross_check="none",
        findings=[("HIGH", "<b>x</b>", "<img>")],
        iocs=[("ip", "1.2.3.4", "<evil>")],
        summary="sum",
    )
    page = render_html(data)
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "&lt;b&gt;x&lt;/b&gt;" in page
    assert "<img>" not in page


def test_render_markdown_includes_empty_sni_row():
    data = ReportData(
        case_id="C",
        pcap_name="n.pcap",
        pcap_bytes=2,
        sha256="cd",
        unchanged=True,
        packets=0,
        t0=0,
        t1=0,
        custody="ok",
        cross_check="none",
        summary="No suspicious activity detected by the current rules.",
    )
    md = render_markdown(data)
    assert "none observed" in md
    assert "## Findings" in md
    assert "## Indicators of compromise" in md


def test_cli_report_rejects_unknown_format():
    with pytest.raises(SystemExit) as exc:
        main(["report", "x.pcap", "--format", "pdf"])
    assert exc.value.code == 2
