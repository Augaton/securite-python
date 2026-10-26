from src.tp2.utils.yara_scan import fallback_scan


def test_given_c2_payload_when_fallback_scan_then_flag_c2_rule():
    matches = fallback_scan(b"beacon http://c2-xx.example.test/gate.php", entropy=4.0)
    assert "suspicious_c2_http" in matches


def test_given_keylogger_strings_when_fallback_scan_then_flag_keylogger_rule():
    assert "keylogger_behavior" in fallback_scan(b"GetAsyncKeyState loop", entropy=4.0)


def test_given_high_entropy_when_fallback_scan_then_flag_packed_rule():
    assert "high_entropy_packed" in fallback_scan(b"random", entropy=7.5)


def test_given_esgi_flag_when_fallback_scan_then_flag_embedded_marker():
    assert "embedded_esgi_flag" in fallback_scan(b"ESGI{abc}", entropy=4.0)


def test_given_benign_data_when_fallback_scan_then_no_match():
    assert fallback_scan(b"plain harmless text", entropy=4.0) == []
