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

    triage = out / "a.bin.triage.json"
    assert triage.exists()
    report = json.loads(triage.read_text(encoding="utf-8"))
    assert report["flag"] == "ESGI{real_a}"
    assert (out / f"{report['sha256']}.json").exists()  # format <sha256>.json du sujet
    assert "ESGI_C2_HTTP_Beacon" in report["yara_matches"]


def test_iter_samples_skips_aux_files(tmp_path):
    from src.tp2.main import lister_echantillons

    (tmp_path / "a.bin").write_bytes(b"x")
    (tmp_path / "GROUP.txt").write_text("grp")
    (tmp_path / "notes.json").write_text("{}")
    assert [p.name for p in lister_echantillons(str(tmp_path))] == ["a.bin"]
