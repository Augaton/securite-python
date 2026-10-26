from src.tp2.utils.triage import Triage


def test_given_sample_when_run_then_result_has_meta_iocs_yara_flag(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_KEY", raising=False)
    sample = tmp_path / "m.bin"
    sample.write_bytes(b"\x7fELF http://c2-1.example.test/gate.php ESGI{real_x} dropper")

    result = Triage(str(sample)).run()

    assert result["file"] == "m.bin"
    assert len(result["meta"]["sha256"]) == 64
    assert result["meta"]["entropy"] >= 0
    assert result["flag"] == "ESGI{real_x}"
    assert "suspicious_c2_http" in result["yara"]
    assert "dropper_behavior" in result["yara"]
    assert "verdict" not in result  # pas de clé LLM -> pas de verdict
