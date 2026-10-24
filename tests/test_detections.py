"""Detection tests against synthetic PCAPs (no large binaries in the repo)."""
from __future__ import annotations

from pathlib import Path

import pytest
from scapy.all import IP, IPv6, rdpcap

from pcaplens.analyze import analyze_pcap, is_internal
from pcaplens.custody import CustodyLog, verify
from pcaplens.synth import (
    C2_6,
    DROP,
    LINKLOCAL6,
    LOOPBACK6,
    PEER_LINKLOCAL6,
    VICTIM,
    VICTIM6,
    build_attack_pcap,
    build_clean_pcap,
    build_dual_stack_pcap,
)


@pytest.fixture(scope="module")
def attack_pcap(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("pcaps") / "attack.pcap"
    return build_attack_pcap(path)


@pytest.fixture(scope="module")
def clean_pcap(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("pcaps") / "clean.pcap"
    return build_clean_pcap(path)


@pytest.fixture(scope="module")
def dual_stack_pcap(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("pcaps") / "dual_stack.pcap"
    return build_dual_stack_pcap(path)


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


def test_dual_stack_capture_has_v4_and_v6(dual_stack_pcap: Path):
    pkts = rdpcap(str(dual_stack_pcap))
    v4 = {ip for p in pkts if IP in p for ip in (p[IP].src, p[IP].dst)}
    v6 = {ip for p in pkts if IPv6 in p for ip in (p[IPv6].src, p[IPv6].dst)}
    assert VICTIM in v4 and DROP in v4
    assert {VICTIM6, C2_6, LINKLOCAL6, PEER_LINKLOCAL6, LOOPBACK6} <= v6
    assert is_internal(VICTIM) and not is_internal(DROP)
    assert is_internal(VICTIM6) and not is_internal(C2_6)
    assert is_internal(LINKLOCAL6) and is_internal(PEER_LINKLOCAL6)
    assert is_internal(LOOPBACK6)


def test_dual_stack_ula_exfil_detected(dual_stack_pcap: Path, tmp_path: Path):
    result = analyze_pcap(
        dual_stack_pcap,
        case_id="TEST-DUAL",
        examiner="pytest",
        out=tmp_path / "out_dual",
        tshark_cross_check=False,
    )
    exfil = [f for f in result.findings if "exfiltration" in f[1].lower()]
    assert len(exfil) == 1
    detail = exfil[0][2]
    assert VICTIM6 in detail
    assert C2_6 in detail
    assert LINKLOCAL6 not in detail
    assert PEER_LINKLOCAL6 not in detail
    assert LOOPBACK6 not in detail
