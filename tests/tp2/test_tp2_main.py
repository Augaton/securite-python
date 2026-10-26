import json

from src.tp2.main import main


def test_main_writes_one_sha256_json_per_sample(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    samples = tmp_path / "samples"
    out = tmp_path / "out"
    samples.mkdir()
    (samples / "a.bin").write_bytes(b"\x7fELF http://c2-1.example.test/gate.php ESGI{real_a}")
    (samples / "GROUP.txt").write_text("grp")  # fichier annexe, doit être ignoré

    main(["--samples", str(samples), "--out", str(out)])

    jsons = list(out.glob("*.json"))
    assert len(jsons) == 1
    report = json.loads(jsons[0].read_text(encoding="utf-8"))
    assert report["flag"] == "ESGI{real_a}"
    assert jsons[0].stem == report["sha256"]
    assert "ESGI_C2_HTTP_Beacon" in report["yara_matches"]
