import json

from src.tp2.utils.report import generate_report

RESULT = {
    "sha256": "abc123",
    "md5": "x",
    "size": 1,
    "entropy": 0.0,
    "file_type": "data",
    "iocs": {"domains": [], "ips": [], "urls": [], "mutex": [], "registry": []},
    "imports": [],
    "yara_matches": [],
    "family_guess": "unknown",
    "mitre_attack": [],
    "llm_summary": "résumé",
    "score": 0,
    "flag": None,
}


def test_generate_report_writes_triage_and_sha256_json(tmp_path):
    path = generate_report(RESULT, str(tmp_path), "sample.bin")

    assert path.name == "sample.bin.triage.json"
    assert (tmp_path / "abc123.json").exists()  # format <sha256>.json du sujet
    assert json.loads(path.read_text(encoding="utf-8"))["sha256"] == "abc123"


def test_generate_pdf_creates_file(tmp_path):
    from src.tp2.utils.report import _generate_pdf

    pdf_path = tmp_path / "r.pdf"
    _generate_pdf(RESULT, pdf_path)
    assert pdf_path.exists() and pdf_path.read_bytes().startswith(b"%PDF")
