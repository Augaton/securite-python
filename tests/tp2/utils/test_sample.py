import pytest

from src.tp2.utils.sample import Sample


def _sample(tmp_path, data: bytes) -> Sample:
    path = tmp_path / "s.bin"
    path.write_bytes(data)
    return Sample(str(path))


def test_given_file_when_get_file_metadata_then_hashes_size_entropy(tmp_path):
    sample = _sample(tmp_path, b"\x7fELF hello world")

    meta = sample.get_file_metadata()

    assert len(meta["sha256"]) == 64
    assert len(meta["md5"]) == 32
    assert meta["size"] == len(b"\x7fELF hello world")
    assert isinstance(meta["file_type"], str) and meta["file_type"]
    assert meta["entropy"] >= 0


@pytest.mark.parametrize("data, expected", [(b"", 0.0), (b"\x00" * 100, 0.0), (bytes(range(256)), 8.0)])
def test_shannon_entropy(tmp_path, data, expected):
    assert _sample(tmp_path, data).shannon_entropy() == pytest.approx(expected)


def test_given_strings_when_extract_iocs_then_urls_ips_domains_emails(tmp_path):
    sample = _sample(tmp_path, b"http://c2-x.example.test/gate.php 185.1.2.3 bug@evil.ru gnu.org libc.so.6")

    iocs = sample.extract_iocs()

    assert iocs["urls"] == ["http://c2-x.example.test/gate.php"]
    assert iocs["ipv4"] == ["185.1.2.3"]
    assert iocs["emails"] == ["bug@evil.ru"]
    assert iocs["domains"] == ["c2-x.example.test", "evil.ru", "gnu.org"]


def test_given_decoy_before_real_when_find_flag_then_return_real(tmp_path):
    assert _sample(tmp_path, b"ESGI{fam_decoy_1} ESGI{fam_real_2}").find_flag() == "ESGI{fam_real_2}"


def test_given_only_decoy_when_find_flag_then_return_none(tmp_path):
    assert _sample(tmp_path, b"ESGI{fam_decoy_1}").find_flag() is None
