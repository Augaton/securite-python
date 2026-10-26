import json

from src.tp2.main import main


def test_given_file_when_main_then_triage_json_written_next_to_input(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_KEY", raising=False)
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x7fELF ESGI{real_abc} http://c2-1.example.test/gate.php")

    main(["-f", str(sample)])

    output = tmp_path / "sample.bin.triage.json"
    assert output.exists()
    data = json.loads(output.read_text())
    assert data["flag"] == "ESGI{real_abc}"
    assert data["meta"]["sha256"]
    assert "suspicious_c2_http" in data["yara"]
