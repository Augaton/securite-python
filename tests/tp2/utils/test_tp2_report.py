import json

from tests.tp2.factory import REAL_FLAG
from tp2.utils.llm import LLMTriage
from tp2.utils.report import Report, generate_report, get_score_color, to_grader_json, to_pdf_text
from tp2.utils.scanner import YaraScanner
from tp2.utils.triage import Triage

GRADER_KEYS = [
    "sha256",
    "md5",
    "size",
    "entropy",
    "file_type",
    "iocs",
    "imports",
    "yara_matches",
    "family_guess",
    "mitre_attack",
    "llm_summary",
    "score",
    "flag",
]


def make_result(path) -> dict:
    return Triage(str(path), scanner=YaraScanner(None), llm=LLMTriage("offline")).run()


def test_to_grader_json_has_exactly_the_keys_of_the_assignment(dropper_path):
    # When
    grader_json = to_grader_json(make_result(dropper_path))

    # Then
    assert list(grader_json) == GRADER_KEYS
    assert list(grader_json["iocs"]) == ["domains", "ips", "urls", "mutex", "registry"]
    assert isinstance(grader_json["size"], int)
    assert isinstance(grader_json["entropy"], float)
    assert 0 <= grader_json["score"] <= 10


def test_generate_report_writes_json_named_after_the_sha256_and_pdf(dropper_path, tmp_path):
    # Given
    result = make_result(dropper_path)

    # When
    json_path = generate_report(result, str(tmp_path))

    # Then
    assert json_path == tmp_path / f"{result['sha256']}.json"
    written = json.loads(json_path.read_text(encoding="utf-8"))
    assert written["flag"] == REAL_FLAG
    assert written["iocs"]["mutex"] == ["Global\\unitmutex01"]
    assert json_path.with_suffix(".pdf").read_bytes().startswith(b"%PDF")


def test_generate_report_without_pdf(dropper_path, tmp_path):
    # When
    json_path = generate_report(make_result(dropper_path), str(tmp_path), pdf=False)

    # Then
    assert json_path.exists()
    assert list(tmp_path.glob("*.pdf")) == []


def test_given_pdf_failure_when_generate_report_then_json_is_kept(
    dropper_path, tmp_path, monkeypatch, caplog
):
    # Given
    def broken_pdf(self, out_pdf):
        raise RuntimeError("fpdf")

    monkeypatch.setattr(Report, "generate_pdf", broken_pdf)

    # When
    json_path = generate_report(make_result(dropper_path), str(tmp_path))

    # Then
    assert json_path.exists()
    assert "non généré" in caplog.text


def test_pdf_of_a_file_without_indicator(tmp_path):
    # Given
    path = tmp_path / "empty.bin"
    path.write_bytes(b"")

    # When
    json_path = generate_report(make_result(path), str(tmp_path))

    # Then
    assert json_path.with_suffix(".pdf").exists()
    assert json.loads(json_path.read_text())["flag"] is None


def test_to_pdf_text_removes_control_characters_and_non_latin1():
    assert to_pdf_text("ok\x1b[31m → é") == "ok [31m ? é"


def test_get_score_color():
    assert get_score_color(0) == get_score_color(3) != get_score_color(5) != get_score_color(10)
