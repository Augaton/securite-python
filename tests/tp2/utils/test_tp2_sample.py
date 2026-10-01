import shutil
import sys
from unittest.mock import patch

import pytest

from tests.tp2.factory import FAKE_DOMAIN, REAL_FLAG
from tp2.utils.sample import Sample, get_file_metadata, get_file_type, parse_binary, shannon_entropy


def test_get_file_metadata():
    # When
    metadata = get_file_metadata(b"abc")

    # Then
    assert metadata["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert metadata["md5"] == "900150983cd24fb0d6963f7d28e17f72"
    assert metadata["size"] == 3
    assert metadata["entropy"] == 1.58
    assert isinstance(metadata["file_type"], str)


@pytest.mark.parametrize(
    ("data", "expected"), [(b"", 0.0), (b"aaaa", 0.0), (b"abab", 1.0), (bytes(range(256)), 8.0)]
)
def test_shannon_entropy(data, expected):
    assert shannon_entropy(data) == pytest.approx(expected)


def test_get_file_type_uses_libmagic():
    pytest.importorskip("magic")

    # When
    file_type = get_file_type(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

    # Then
    assert file_type.startswith("PDF document")


def test_get_file_type_without_libmagic_reads_the_first_bytes():
    # Given
    with patch.dict(sys.modules, {"magic": None}):
        # When
        elf_type = get_file_type(b"\x7fELF\x02\x01")
        unknown_type = get_file_type(b"\x00\x01\x02")

    # Then
    assert elf_type == "ELF"
    assert unknown_type == "data"


def test_parse_binary_of_a_non_binary_file(tmp_path):
    # Given
    path = tmp_path / "notes.txt"
    path.write_text("just some text")

    # When
    info = parse_binary(str(path))

    # Then
    assert info == {
        "format": None,
        "imports": [],
        "exports": [],
        "libraries": [],
        "sections": [],
        "overlay": {},
    }


@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="l'interpréteur Python n'est un ELF que sous Linux"
)
def test_parse_binary_reads_imports_sections_and_overlay_of_an_elf(tmp_path):
    # Given
    pytest.importorskip("lief")
    path = tmp_path / "python.bin"
    shutil.copyfile(sys.executable, path)
    with path.open("ab") as binary:
        binary.write(b"--- overlay ---\x00payload")

    # When
    info = parse_binary(str(path))

    # Then
    assert info["format"] == "ELF"
    assert info["imports"]
    assert any(section["name"] == ".text" for section in info["sections"])
    assert info["overlay"]["size"] == len(b"--- overlay ---\x00payload")
    assert info["overlay"]["offset"] == path.stat().st_size - info["overlay"]["size"]


def test_sample(dropper_path):
    # When
    sample = Sample(str(dropper_path))

    # Then
    assert sample.name == "dropper.bin"
    assert sample.get_file_metadata()["size"] == dropper_path.stat().st_size
    assert sample.shannon_entropy() > 0
    assert sample.extract_iocs()["domains"] == [FAKE_DOMAIN]
    assert sample.get_flag() == REAL_FLAG
    assert len(sample.get_prompt_injections()) == 2
    assert set(sample.parse_binary()) == {"format", "imports", "exports", "libraries", "sections", "overlay"}
