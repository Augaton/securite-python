import hashlib
import json
import logging

import pytest

from tests.tp2.factory import REAL_FLAG, build_sample
from tp2.main import find_samples, main, parse_arguments


@pytest.fixture
def samples_dir(tmp_path, dropper_data):
    directory = tmp_path / "samples"
    (directory / "sub").mkdir(parents=True)
    (directory / "dropper.bin").write_bytes(dropper_data)
    (directory / "sub" / "notes.txt").write_bytes(build_sample("Usage: notes [FILE]", header=b""))
    (directory / ".hidden").write_bytes(b"ignored")
    return directory


def run_main(samples_dir, tmp_path, *options: str):
    out_dir = tmp_path / "out"
    main(["--samples", str(samples_dir), "--rules", str(tmp_path / "rules"), "--out", str(out_dir), *options])
    return out_dir


def test_main_writes_one_json_per_sample_named_after_its_sha256(samples_dir, tmp_path, dropper_data):
    # When
    out_dir = run_main(samples_dir, tmp_path, "--llm", "offline")

    # Then
    dropper_sha256 = hashlib.sha256(dropper_data).hexdigest()
    assert len(list(out_dir.glob("*.json"))) == 2
    assert len(list(out_dir.glob("*.pdf"))) == 2
    report = json.loads((out_dir / f"{dropper_sha256}.json").read_text(encoding="utf-8"))
    assert report["sha256"] == dropper_sha256
    assert report["flag"] == REAL_FLAG
    assert report["score"] >= 8


def test_main_without_pdf(samples_dir, tmp_path):
    # When
    out_dir = run_main(samples_dir, tmp_path, "--llm", "offline", "--no-pdf")

    # Then
    assert len(list(out_dir.glob("*.json"))) == 2
    assert list(out_dir.glob("*.pdf")) == []


def test_given_failing_sample_when_main_then_next_samples_are_analysed(samples_dir, tmp_path, caplog):
    # Given
    caplog.set_level(logging.ERROR)
    (samples_dir / "unreadable.bin").write_bytes(b"x")
    (samples_dir / "unreadable.bin").chmod(0)

    # When
    out_dir = run_main(samples_dir, tmp_path, "--llm", "offline", "--no-pdf")

    # Then
    assert len(list(out_dir.glob("*.json"))) >= 2


def test_find_samples(samples_dir):
    # When
    samples = find_samples(str(samples_dir), [str(samples_dir / "dropper.bin")])

    # Then
    assert [path.name for path in samples] == ["dropper.bin", "notes.txt"]


def test_parse_arguments_of_the_grader():
    # When
    options = parse_arguments(["--samples", "in", "--rules", "rules", "--out", "out", "--unknown"])

    # Then
    assert (options.samples, options.rules, options.out, options.no_pdf) == ("in", "rules", "out", False)


def test_parse_arguments_takes_the_llm_from_the_environment(monkeypatch):
    # Given
    monkeypatch.setenv("LLM_BACKEND", "Offline")

    # When
    options = parse_arguments(["-f", "sample.bin"])

    # Then
    assert options.llm == "offline"
    assert options.file == ["sample.bin"]


@pytest.mark.parametrize("arguments", [["--out", "out"], ["--samples", "in", "--llm", "chatgpt"]])
def test_parse_arguments_errors(arguments):
    with pytest.raises(SystemExit):
        parse_arguments(arguments)
