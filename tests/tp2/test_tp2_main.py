import json

from src.tp2.main import main


def test_given_samples_dir_when_main_then_one_triage_json_per_sample(tmp_path):
    # Given
    (tmp_path / "a.bin").write_bytes(b"\x7fELF ESGI{real_aaa} http://c2-1.example.test/gate.php")
    (tmp_path / "b.bin").write_bytes(b"\x7fELF ESGI{real_bbb} dropper")
    (tmp_path / "GROUP.txt").write_text("grp")  # fichier annexe, doit être ignoré

    # When
    main([str(tmp_path)])

    # Then
    assert (tmp_path / "a.bin.triage.json").exists()
    assert (tmp_path / "b.bin.triage.json").exists()
    assert not (tmp_path / "GROUP.txt.triage.json").exists()

    report = json.loads((tmp_path / "a.bin.triage.json").read_text())
    assert report["flag"] == "ESGI{real_aaa}"
    assert "suspicious_c2_http" in report["yara"]


def test_given_no_sample_when_main_then_warn_without_crashing(tmp_path, caplog):
    # When
    main([str(tmp_path)])

    # Then
    assert "Aucun échantillon à analyser" in caplog.text
