from src.tp2.utils.scanner import _fallback, yara_scan


def test_fallback_detects_c2():
    assert "ESGI_C2_HTTP_Beacon" in _fallback(b"beacon /gate.php to c2-abc")


def test_fallback_detects_keylogger():
    assert "ESGI_Keylogger_Behavior" in _fallback(b"GetAsyncKeyState loop")


def test_fallback_detects_high_entropy():
    assert "ESGI_High_Entropy_Payload" in _fallback(bytes(range(256)) * 4)


def test_fallback_benign_data():
    assert _fallback(b"plain harmless text") == []


def test_yara_scan_returns_list_and_matches_c2():
    # yara installé -> compile rules/ ; sinon -> repli : dans les deux cas une liste avec la règle C2
    result = yara_scan(b"GET /gate.php from c2-abc", None)
    assert isinstance(result, list)
    assert "ESGI_C2_HTTP_Beacon" in result


def test_entropy_bounds():
    import pytest

    from src.tp2.utils.scanner import _entropy

    assert _entropy(b"") == 0.0
    assert _entropy(bytes(range(256))) == pytest.approx(8.0)
