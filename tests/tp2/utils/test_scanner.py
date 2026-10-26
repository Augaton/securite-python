from src.tp2.utils.scanner import YaraScanner


def test_given_c2_payload_then_flag_c2_rule():
    assert "suspicious_c2_http" in YaraScanner._fallback(b"beacon http://c2-x.example.test/gate.php")


def test_given_keylogger_strings_then_flag_keylogger_rule():
    assert "keylogger_behavior" in YaraScanner._fallback(b"GetAsyncKeyState loop")


def test_given_high_entropy_then_flag_packed_rule():
    assert "high_entropy_packed" in YaraScanner._fallback(bytes(range(256)) * 4)


def test_given_esgi_flag_then_flag_embedded_marker():
    assert "embedded_esgi_flag" in YaraScanner._fallback(b"ESGI{abc}")


def test_given_benign_data_then_no_match():
    assert YaraScanner._fallback(b"plain harmless text") == []


def test_scan_falls_back_without_yara():
    assert "suspicious_c2_http" in YaraScanner().scan(b"/gate.php c2-abc")
