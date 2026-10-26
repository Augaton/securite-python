from src.tp2.utils import verdict

META_PACKED = {"entropy": 7.5}
META_NORMAL = {"entropy": 4.0}
NET_IOCS = {"urls": ["http://c2/gate.php"], "ips": ["1.2.3.4"], "domains": ["c2.test"], "mutex": [], "registry": []}
EMPTY_IOCS = {"urls": [], "ips": [], "domains": [], "mutex": [], "registry": []}


def test_guess_family_from_yara():
    assert verdict.guess_family(["ESGI_Keylogger_Behavior"], EMPTY_IOCS) == "keylogger"


def test_guess_family_network_fallback():
    assert verdict.guess_family([], NET_IOCS) == "backdoor"


def test_guess_family_unknown():
    assert verdict.guess_family([], EMPTY_IOCS) == "unknown"


def test_map_mitre_c2_and_packed():
    techniques = verdict.map_mitre(["ESGI_C2_HTTP_Beacon"], NET_IOCS, META_PACKED)
    assert "T1071" in techniques and "T1027" in techniques


def test_compute_score_high_for_c2_and_bounded():
    score = verdict.compute_score(["ESGI_C2_HTTP_Beacon"], NET_IOCS, META_NORMAL)
    assert 4 <= score <= 10


def test_compute_score_zero_for_benign():
    assert verdict.compute_score([], EMPTY_IOCS, META_NORMAL) == 0


def test_build_features_caps_imports_and_excludes_binary():
    features = verdict.build_features({"file_type": "ELF", "entropy": 4.0}, EMPTY_IOCS, [], ["f"] * 100)
    assert len(features["imports"]) <= 40
    assert "raw" not in features and "data" not in features


def test_deterministic_summary_mentions_family_and_score():
    summary = verdict.deterministic_summary("backdoor", 6, ["R"], NET_IOCS)
    assert "backdoor" in summary and "6/10" in summary
