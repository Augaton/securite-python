from unittest.mock import MagicMock

import pytest

from src.tp3.utils.fuzzer import (
    _looks_like_hit,
    find_hidden_endpoint,
    load_words,
)


class _Resp:
    def __init__(self, status_code, content=b""):
        self.status_code = status_code
        self.content = content


def test_load_words_skips_comments_and_blanks(tmp_path):
    wl = tmp_path / "w.txt"
    wl.write_text("# commentaire\n\nadmin\n/secret/\n", encoding="utf-8")
    assert load_words(wl) == ["admin", "secret"]


def test_embedded_wordlist_loads():
    words = load_words()
    assert "admin" in words
    assert len(words) > 20


def test_looks_like_hit():
    assert _looks_like_hit(_Resp(200), nf_status=404, nf_len=50) is True
    assert _looks_like_hit(_Resp(403), nf_status=404, nf_len=50) is True
    assert _looks_like_hit(_Resp(404), nf_status=404, nf_len=50) is False
    # serveur qui repond 200 a tout : separe par la taille du corps
    assert _looks_like_hit(_Resp(200, b"x" * 500), nf_status=200, nf_len=50) is True


def test_find_hidden_endpoint_returns_first_hit(tmp_path):
    wl = tmp_path / "w.txt"
    wl.write_text("nope\nsecret\n", encoding="utf-8")
    session = MagicMock()

    def fake_get(url, **kwargs):
        if "secret" in url:
            return _Resp(200, b"hello")
        return _Resp(404)

    session.get.side_effect = fake_get
    url, resp = find_hidden_endpoint("http://t", session, wl)
    assert url == "http://t/secret"
    assert resp.status_code == 200


def test_find_hidden_endpoint_raises_when_nothing(tmp_path):
    wl = tmp_path / "w.txt"
    wl.write_text("nope\n", encoding="utf-8")
    session = MagicMock()
    session.get.return_value = _Resp(404)
    with pytest.raises(RuntimeError):
        find_hidden_endpoint("http://t", session, wl)
