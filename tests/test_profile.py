"""YAML detection-threshold profile loading and override behaviour."""
from __future__ import annotations

from pathlib import Path

import pytest

from pcaplens.analyze import analyze_pcap
from pcaplens.cli import main
from pcaplens.synth import build_attack_pcap, build_clean_pcap
from pcaplens.thresholds import ProfileError, Thresholds, load_profile

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_YAML = REPO_ROOT / "profiles" / "default.yaml"


def _write_yaml(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


def test_builtin_defaults_match_published_constants():
    """Thresholds() is the built-in default used when --profile is omitted."""
    t = Thresholds()
    assert t.SCAN_PORTS == 50
    assert t.SCAN_WINDOW == 60
    assert t.BEACON_MIN_CONNS == 6
    assert t.BEACON_TOLERANCE == 0.10
    assert t.BEACON_MIN_RATIO == 0.80
    assert t.DNS_LABEL_LEN == 40
    assert t.DNS_ENTROPY == 3.5
    assert t.EXFIL_BYTES == 100_000


def test_default_yaml_matches_builtins_exactly():
    loaded = load_profile(DEFAULT_YAML)
    assert loaded == Thresholds()


def test_partial_profile_keeps_unspecified_defaults(tmp_path: Path):
    path = _write_yaml(tmp_path / "partial.yaml", "EXFIL_BYTES: 1\n")
    loaded = load_profile(path)
    assert loaded.EXFIL_BYTES == 1
    assert loaded.SCAN_PORTS == Thresholds().SCAN_PORTS
    assert loaded.BEACON_TOLERANCE == Thresholds().BEACON_TOLERANCE


def test_profile_overrides_suppress_port_scan(tmp_path: Path):
    """Raising SCAN_PORTS above the synthetic scan must drop that finding."""
    pcap = build_attack_pcap(tmp_path / "attack.pcap")
    baseline = analyze_pcap(
        pcap,
        case_id="PROF-BASE",
        out=tmp_path / "out_base",
        tshark_cross_check=False,
    )
    assert any("Port scan" in title for _, title, _ in baseline.findings)

    profile = _write_yaml(tmp_path / "quiet_scan.yaml", "SCAN_PORTS: 10000\n")
    quiet = analyze_pcap(
        pcap,
        case_id="PROF-QUIET",
        out=tmp_path / "out_quiet",
        tshark_cross_check=False,
        thresholds=load_profile(profile),
    )
    assert not any("Port scan" in title for _, title, _ in quiet.findings)
    # Other attack classes must still fire so the override is specific.
    titles = {title for _, title, _ in quiet.findings}
    assert any("beacon" in title.lower() for title in titles)
    assert "Possible data exfiltration" in titles


def test_profile_overrides_suppress_exfil(tmp_path: Path):
    pcap = build_attack_pcap(tmp_path / "attack.pcap")
    profile = _write_yaml(tmp_path / "huge_exfil.yaml", "EXFIL_BYTES: 10000000\n")
    result = analyze_pcap(
        pcap,
        case_id="PROF-EXFIL",
        out=tmp_path / "out_exfil",
        tshark_cross_check=False,
        thresholds=load_profile(profile),
    )
    assert not any(title == "Possible data exfiltration" for _, title, _ in result.findings)


def test_unknown_key_is_a_clear_error(tmp_path: Path):
    path = _write_yaml(tmp_path / "unknown.yaml", "NOT_A_THRESHOLD: 1\nSCAN_PORTS: 10\n")
    with pytest.raises(ProfileError, match="unknown key") as exc:
        load_profile(path)
    assert "NOT_A_THRESHOLD" in str(exc.value)


def test_wrong_type_is_a_clear_error(tmp_path: Path):
    path = _write_yaml(tmp_path / "bad_type.yaml", "SCAN_PORTS: fifty\n")
    with pytest.raises(ProfileError, match="SCAN_PORTS") as exc:
        load_profile(path)
    assert "integer" in str(exc.value).lower()
    assert "invalid profile" in str(exc.value)


def test_bool_is_rejected_as_wrong_type(tmp_path: Path):
    # YAML true becomes bool; bool is a subclass of int and must not sneak through.
    path = _write_yaml(tmp_path / "bool.yaml", "SCAN_PORTS: true\n")
    with pytest.raises(ProfileError, match="SCAN_PORTS"):
        load_profile(path)


def test_bad_yaml_is_a_clear_error(tmp_path: Path):
    path = _write_yaml(tmp_path / "broken.yaml", "SCAN_PORTS: [unterminated\n")
    with pytest.raises(ProfileError, match="YAML") as exc:
        load_profile(path)
    msg = str(exc.value)
    assert "broken.yaml" in msg
    assert "invalid profile" in msg
    assert "unicode string" not in msg


def test_non_mapping_profile_is_a_clear_error(tmp_path: Path):
    path = _write_yaml(tmp_path / "list.yaml", "- SCAN_PORTS: 50\n")
    with pytest.raises(ProfileError, match="mapping"):
        load_profile(path)


def test_cli_profile_default_yaml(tmp_path: Path):
    pcap = build_clean_pcap(tmp_path / "clean.pcap")
    out = tmp_path / "out"
    rc = main(
        [
            "analyse",
            str(pcap),
            "--profile",
            str(DEFAULT_YAML),
            "--out",
            str(out),
            "--no-tshark",
        ]
    )
    assert rc == 0
    assert (out / "report.md").is_file()


def test_empty_file_is_a_clear_error(tmp_path: Path):
    path = _write_yaml(tmp_path / "empty.yaml", "")
    with pytest.raises(ProfileError, match="empty") as exc:
        load_profile(path)
    assert "invalid profile" in str(exc.value)
    assert "empty.yaml" in str(exc.value)


def test_comment_only_file_is_a_clear_error(tmp_path: Path):
    path = _write_yaml(tmp_path / "comments.yaml", "# no keys\n")
    with pytest.raises(ProfileError, match="empty"):
        load_profile(path)


def test_null_value_is_a_clear_error(tmp_path: Path):
    path = _write_yaml(tmp_path / "null.yaml", "SCAN_PORTS: null\n")
    with pytest.raises(ProfileError, match="SCAN_PORTS") as exc:
        load_profile(path)
    assert "null" in str(exc.value)


def test_zero_threshold_is_rejected(tmp_path: Path):
    path = _write_yaml(tmp_path / "zero.yaml", "EXFIL_BYTES: 0\n")
    with pytest.raises(ProfileError, match="EXFIL_BYTES") as exc:
        load_profile(path)
    assert "greater than 0" in str(exc.value)


def test_negative_threshold_is_rejected(tmp_path: Path):
    path = _write_yaml(tmp_path / "neg.yaml", "SCAN_PORTS: -3\n")
    with pytest.raises(ProfileError, match="SCAN_PORTS") as exc:
        load_profile(path)
    assert "greater than 0" in str(exc.value)


def test_beacon_min_conns_below_two_is_rejected(tmp_path: Path):
    path = _write_yaml(tmp_path / "one.yaml", "BEACON_MIN_CONNS: 1\n")
    with pytest.raises(ProfileError, match="at least 2"):
        load_profile(path)


def test_negative_float_is_rejected(tmp_path: Path):
    path = _write_yaml(tmp_path / "negf.yaml", "BEACON_TOLERANCE: -0.1\n")
    with pytest.raises(ProfileError, match="BEACON_TOLERANCE"):
        load_profile(path)


def test_ratio_above_one_is_rejected(tmp_path: Path):
    path = _write_yaml(tmp_path / "ratio.yaml", "BEACON_MIN_RATIO: 1.5\n")
    with pytest.raises(ProfileError, match="between 0 and 1"):
        load_profile(path)


def test_nested_unknown_section_is_rejected(tmp_path: Path):
    path = _write_yaml(tmp_path / "nested.yaml", "detections:\n  SCAN_PORTS: 50\n")
    with pytest.raises(ProfileError, match="unknown key") as exc:
        load_profile(path)
    assert "detections" in str(exc.value)


def test_nested_value_for_known_key_is_rejected(tmp_path: Path):
    path = _write_yaml(tmp_path / "nested_val.yaml", "SCAN_PORTS:\n  count: 50\n")
    with pytest.raises(ProfileError, match="SCAN_PORTS") as exc:
        load_profile(path)
    assert "integer" in str(exc.value).lower()


def test_missing_file_is_a_clear_error(tmp_path: Path):
    missing = tmp_path / "does-not-exist.yaml"
    with pytest.raises(ProfileError, match="file not found") as exc:
        load_profile(missing)
    assert "does-not-exist.yaml" in str(exc.value)


def test_empty_mapping_keeps_all_defaults(tmp_path: Path):
    path = _write_yaml(tmp_path / "empty_map.yaml", "{}\n")
    assert load_profile(path) == Thresholds()


def test_non_finite_float_is_rejected(tmp_path: Path):
    path = _write_yaml(tmp_path / "inf.yaml", "BEACON_TOLERANCE: .inf\n")
    with pytest.raises(ProfileError, match="finite"):
        load_profile(path)


def test_mixed_unknown_keys_are_listed(tmp_path: Path):
    path = _write_yaml(tmp_path / "mixed.yaml", "FOO: 1\n123: 2\n")
    with pytest.raises(ProfileError, match="unknown key") as exc:
        load_profile(path)
    assert "FOO" in str(exc.value)
    assert "123" in str(exc.value)


def test_analyze_survives_min_conns_of_one(tmp_path: Path):
    """Library-built Thresholds can skip YAML checks; the detector must not crash."""
    pcap = build_clean_pcap(tmp_path / "clean.pcap")
    result = analyze_pcap(
        pcap,
        case_id="PROF-SAFE",
        out=tmp_path / "out",
        tshark_cross_check=False,
        thresholds=Thresholds(BEACON_MIN_CONNS=1),
    )
    assert result.findings == []


def test_directory_path_is_a_clear_error(tmp_path: Path):
    with pytest.raises(ProfileError, match="directory") as exc:
        load_profile(tmp_path)
    assert "invalid profile" in str(exc.value)


def test_non_utf8_file_is_a_clear_error(tmp_path: Path):
    path = tmp_path / "binary.yaml"
    path.write_bytes(b"\xff\xfe SCAN_PORTS: 50\n")
    with pytest.raises(ProfileError, match="UTF-8"):
        load_profile(path)


def test_cli_invalid_profile_exits_nonzero(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    bad = _write_yaml(tmp_path / "bad.yaml", "NOPE: 1\n")
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "analyse",
                str(tmp_path / "missing.pcap"),
                "--profile",
                str(bad),
                "--out",
                str(tmp_path / "out"),
                "--no-tshark",
            ]
        )
    assert exc.value.code != 0
    err = capsys.readouterr().err
    assert "invalid profile" in err
    assert "unknown key" in err
    assert "NOPE" in err


def test_cli_missing_profile_exits_nonzero(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "analyse",
                str(tmp_path / "missing.pcap"),
                "--profile",
                str(tmp_path / "nope.yaml"),
                "--no-tshark",
            ]
        )
    assert exc.value.code != 0
    err = capsys.readouterr().err
    assert "file not found" in err
    assert "nope.yaml" in err
