import pytest

from src.tp2.utils.analysis import (
    extraire_iocs,
    trouver_vrai_flag,
    recup_meta_fichier,
    parser_binaire_lief,
    calc_entropie_shannon,
)


def test_get_file_metadata():
    data = b"\x7fELF hello world"
    meta = recup_meta_fichier(data)
    assert len(meta["sha256"]) == 64
    assert len(meta["md5"]) == 32
    assert meta["size"] == len(data)
    assert isinstance(meta["file_type"], str) and meta["file_type"]
    assert meta["entropy"] >= 0


@pytest.mark.parametrize("data, expected", [(b"", 0.0), (b"\x00" * 100, 0.0), (bytes(range(256)), 8.0)])
def test_shannon_entropy(data, expected):
    assert calc_entropie_shannon(data) == pytest.approx(expected)


def test_extract_iocs():
    data = (
        b"http://c2-x.example.test/gate.php 185.1.2.3 bug@evil.ru "
        b"Global\\mutex123 HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svc gnu.org libc.so.6"
    )
    iocs = extraire_iocs(data)
    assert "http://c2-x.example.test/gate.php" in iocs["urls"]
    assert iocs["ips"] == ["185.1.2.3"]
    assert "c2-x.example.test" in iocs["domains"]
    assert iocs["mutex"] == ["Global\\mutex123"]
    assert iocs["registry"] == ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svc"]
    assert "libc.so" not in iocs["domains"]  # un nom de fichier n'est pas un domaine


def test_find_flag_skips_decoy():
    assert trouver_vrai_flag(b"ESGI{fam_decoy_1} ESGI{fam_real_2}") == "ESGI{fam_real_2}"


def test_find_flag_returns_none_without_real_flag():
    assert trouver_vrai_flag(b"ESGI{only_decoy_1}") is None


def test_parse_binary_returns_expected_keys(tmp_path):
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"\x7fELF")
    result = parser_binaire_lief(str(sample))
    assert set(result) == {"imports", "exports", "sections"}


def test_detect_file_type_elf():
    from src.tp2.utils.analysis import detect_type_fichier

    assert "ELF" in detect_type_fichier(b"\x7fELF\x02\x01\x01")


def test_valid_ipv4():
    from src.tp2.utils.analysis import _verif_ipv4

    assert _verif_ipv4("185.1.2.3")
    assert not _verif_ipv4("999.1.1.1")


@pytest.mark.parametrize(
    "data, expected",
    [
        (b"\x7fELF\x02", "ELF binary"),
        (b"MZ\x90", "PE32 executable"),
        (b"PK\x03\x04", "Zip archive"),
        (b"??", "data"),
    ],
)
def test_detect_type_octets_magiques(data, expected):
    from src.tp2.utils.analysis import detect_type_octets_magiques

    assert detect_type_octets_magiques(data) == expected
