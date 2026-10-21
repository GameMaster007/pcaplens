"""Detection tests against synthetic PCAPs (no large binaries in the repo)."""
from __future__ import annotations

from pathlib import Path

import pytest

from pcaplens.analyze import analyze_pcap
from pcaplens.custody import CustodyLog, verify
from pcaplens.synth import build_attack_pcap, build_clean_pcap


@pytest.fixture(scope="module")
def attack_pcap(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("pcaps") / "attack.pcap"
    return build_attack_pcap(path)


@pytest.fixture(scope="module")
def clean_pcap(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("pcaps") / "clean.pcap"
    return build_clean_pcap(path)


@pytest.fixture
def attack_result(attack_pcap: Path, tmp_path: Path):
    return analyze_pcap(
        attack_pcap,
        case_id="TEST-ATTACK",
        examiner="pytest",
        out=tmp_path / "out_attack",
        tshark_cross_check=False,
    )


@pytest.fixture
def clean_result(clean_pcap: Path, tmp_path: Path):
    return analyze_pcap(
        clean_pcap,
        case_id="TEST-CLEAN",
        examiner="pytest",
        out=tmp_path / "out_clean",
        tshark_cross_check=False,
    )


def _titles(result) -> set[str]:
    return {t for _, t, _ in result.findings}


def test_clean_pcap_no_findings(clean_result):
    assert clean_result.findings == []
    assert clean_result.packets > 0
    assert clean_result.unchanged is True


def test_executable_download_detected(attack_result):
    assert any("Executable" in t for t in _titles(attack_result))


def test_beaconing_detected(attack_result):
    assert any("beacon" in t.lower() for t in _titles(attack_result))


def test_dns_tunnelling_detected(attack_result):
    assert any("DNS tunnelling" in t or "tunnel" in t.lower() for t in _titles(attack_result))


def test_port_scan_detected(attack_result):
    assert any("Port scan" in t for t in _titles(attack_result))


def test_exfiltration_detected(attack_result):
    assert any("exfiltration" in t.lower() for t in _titles(attack_result))


def test_cleartext_ftp_detected(attack_result):
    assert any("credential" in t.lower() for t in _titles(attack_result))


def test_report_and_iocs_written(attack_result):
    assert attack_result.report_path is not None
    assert attack_result.report_path.is_file()
    out = attack_result.report_path.parent
    assert (out / "iocs.csv").is_file()
    assert (out / "events.csv").is_file()
    assert (out / "chain_of_custody.jsonl").is_file()
    assert len(attack_result.iocs) >= 3


def test_custody_chain_intact(attack_result):
    log = attack_result.report_path.parent / "chain_of_custody.jsonl"
    ok, msg = verify(log)
    assert ok, msg


def test_custody_tamper_detected(tmp_path: Path):
    log_path = tmp_path / "coc.jsonl"
    log = CustodyLog(log_path, "TAMPER", examiner="pytest")
    log.record("a", x=1)
    log.record("b", x=2)
    text = log_path.read_text()
    # flip a digit in the first entry body
    log_path.write_text(text.replace('"x": 1', '"x": 9', 1))
    ok, msg = verify(log_path)
    assert not ok
    assert "modified" in msg or "broken" in msg


def test_pcap_hash_unchanged(attack_result):
    assert attack_result.unchanged is True
    assert len(attack_result.sha256) == 64
