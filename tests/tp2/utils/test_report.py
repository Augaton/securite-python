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


def test_generate_report_writes_sha256_json(tmp_path):
    path = generate_report(RESULT, str(tmp_path))

    assert path.name == "abc123.json"
    assert json.loads(path.read_text(encoding="utf-8"))["sha256"] == "abc123"
