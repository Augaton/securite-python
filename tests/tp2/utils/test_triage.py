import pytest

from src.tp2.utils.triage import (
    detect_file_type,
    extract_iocs,
    find_flag,
    shannon_entropy,
    triage,
)


@pytest.mark.parametrize(
    "data, expected",
    [(b"", 0.0), (b"\x00" * 100, 0.0), (bytes(range(256)), 8.0)],
)
def test_shannon_entropy(data, expected):
    assert shannon_entropy(data) == pytest.approx(expected)


@pytest.mark.parametrize(
    "data, expected",
    [(b"\x7fELFrest", "ELF"), (b"MZ...", "PE"), (b"PK\x03\x04", "ZIP"), (b"hello", "data")],
)
def test_detect_file_type(data, expected):
    assert detect_file_type(data) == expected


def test_given_strings_when_extract_iocs_then_return_urls_ips_domains_emails():
    data = b"GET http://c2-dead.example.test/gate.php from 185.10.20.30 mail bug@evil.ru gnu.org libc.so.6"

    result = extract_iocs(data)

    assert result["urls"] == ["http://c2-dead.example.test/gate.php"]
    assert result["ipv4"] == ["185.10.20.30"]
    assert result["emails"] == ["bug@evil.ru"]
    # file names like libc.so.6 are not mistaken for domains
    assert result["domains"] == ["c2-dead.example.test", "evil.ru", "gnu.org"]


def test_given_decoy_before_real_when_find_flag_then_return_the_real_one():
    assert find_flag(b"x ESGI{family_decoy_111} y ESGI{family_real_222} z") == "ESGI{family_real_222}"


def test_given_only_decoy_when_find_flag_then_return_none():
    assert find_flag(b"ESGI{family_decoy_111}") is None


def test_given_no_marker_when_find_flag_then_return_none():
    assert find_flag(b"nothing here") is None


def test_given_sample_when_triage_then_report_has_every_field(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x7fELF http://c2-1.example.test/gate.php ESGI{real_abcdef} dropper")

    report = triage(sample)

    assert report["file"] == "sample.bin"
    assert report["file_type"] == "ELF"
    assert len(report["sha256"]) == 64
    assert report["flag"] == "ESGI{real_abcdef}"
    assert "suspicious_c2_http" in report["yara"]
    assert "dropper_behavior" in report["yara"]
    assert report["iocs"]["urls"] == ["http://c2-1.example.test/gate.php"]
