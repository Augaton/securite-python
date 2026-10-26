import pytest

from src.tp2.utils.analysis import (
    extract_iocs,
    find_flag,
    get_file_metadata,
    parse_binary,
    shannon_entropy,
)


def test_get_file_metadata():
    data = b"\x7fELF hello world"
    meta = get_file_metadata(data)
    assert len(meta["sha256"]) == 64
    assert len(meta["md5"]) == 32
    assert meta["size"] == len(data)
    assert isinstance(meta["file_type"], str) and meta["file_type"]
    assert meta["entropy"] >= 0


@pytest.mark.parametrize("data, expected", [(b"", 0.0), (b"\x00" * 100, 0.0), (bytes(range(256)), 8.0)])
def test_shannon_entropy(data, expected):
    assert shannon_entropy(data) == pytest.approx(expected)


def test_extract_iocs():
    data = (b"http://c2-x.example.test/gate.php 185.1.2.3 bug@evil.ru "
            b"Global\\mutex123 HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svc gnu.org libc.so.6")
    iocs = extract_iocs(data)
    assert "http://c2-x.example.test/gate.php" in iocs["urls"]
    assert iocs["ips"] == ["185.1.2.3"]
    assert "c2-x.example.test" in iocs["domains"]
    assert iocs["mutex"] == ["Global\\mutex123"]
    assert iocs["registry"] == ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svc"]
    assert "libc.so" not in iocs["domains"]  # un nom de fichier n'est pas un domaine


def test_find_flag_skips_decoy():
    assert find_flag(b"ESGI{fam_decoy_1} ESGI{fam_real_2}") == "ESGI{fam_real_2}"


def test_find_flag_returns_none_without_real_flag():
    assert find_flag(b"ESGI{only_decoy_1}") is None


def test_parse_binary_returns_expected_keys(tmp_path):
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"\x7fELF")
    result = parse_binary(str(sample))
    assert set(result) == {"imports", "exports", "sections"}
