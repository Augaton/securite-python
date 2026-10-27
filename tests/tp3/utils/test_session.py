from unittest.mock import MagicMock, patch

from src.tp3.utils.session import WebPhase, _PageParser


class _FakeResponse:
    def __init__(self, text="", json_data=None):
        self.text = text
        self._json = json_data

    def json(self):
        if self._json is None:
            raise ValueError("pas de JSON")
        return self._json


def test_page_parser_finds_image_and_form():
    html = (
        '<html><body><img src="/img/c.png">'
        '<form action="/check" method="post">'
        '<input type="text" name="captcha">'
        '<input type="hidden" name="csrf" value="x">'
        "</form></body></html>"
    )
    parser = _PageParser()
    parser.feed(html)
    assert parser.images == ["/img/c.png"]
    assert parser.form_action == "/check"
    assert parser.form_method == "post"
    assert parser.fields == ["captcha"]  # le champ cache est ignore


def test_extract_from_text():
    phase = WebPhase("http://localhost:8080")
    resp = _FakeResponse(text="Bravo ! FLAG1: ESGI{web_abc} host: 10.0.0.5 port: 9090 key: s3cr3t")
    data = phase._extraire_infos_page(resp)
    assert data["flag1"] == "ESGI{web_abc}"
    assert data["host"] == "10.0.0.5"
    assert data["port"] == 9090
    assert data["key"] == "s3cr3t"


def test_extract_from_hostport_pattern():
    phase = WebPhase("http://localhost:8080")
    resp = _FakeResponse(text="connect to localhost:9090 key=abcd ESGI{x}")
    data = phase._extraire_infos_page(resp)
    assert data["host"] == "localhost"
    assert data["port"] == 9090


def test_extract_from_json():
    phase = WebPhase("http://localhost:8080")
    resp = _FakeResponse(json_data={"flag1": "ESGI{json}", "host": "h", "port": 7000, "key": "k"})
    data = phase._extraire_infos_page(resp)
    assert data == {"flag1": "ESGI{json}", "host": "h", "port": 7000, "key": "k"}


def test_find_captcha_image_from_page():
    phase = WebPhase("http://localhost:8080")
    phase.endpoint = "http://localhost:8080/secret"
    parser = _PageParser()
    parser.images = ["captcha.png"]
    assert phase._trouver_img_captcha(parser) == "http://localhost:8080/secret/captcha.png"


@patch("src.tp3.utils.session.trouver_ep_cache")
@patch("src.tp3.utils.session.Captcha")
def test_run_returns_data_once_captcha_passes(mock_captcha, mock_find):
    phase = WebPhase("http://localhost:8080")
    phase.endpoint = "http://localhost:8080/secret"
    mock_find.return_value = ("http://localhost:8080/secret", _FakeResponse())
    mock_captcha.return_value.solve.return_value = "GOOD"
    phase.session = MagicMock()
    phase.session.get.return_value = _FakeResponse(text="<img src='c.png'><form></form>")
    phase.session.post.return_value = _FakeResponse(text="ESGI{web_ok} host: 10.0.0.1 port: 9090 key: zzz")

    data = phase.derouler_phase_web()
    assert data["flag1"] == "ESGI{web_ok}"
    assert data["host"] == "10.0.0.1"
    assert data["port"] == 9090
    assert data["key"] == "zzz"


def test_verif_infos_completes_needs_flag_host_port_and_key():
    from src.tp3.utils.session import verif_infos_completes

    complet = {"flag1": "ESGI{a}", "host": "127.0.0.1", "port": 9001, "key": "k3y"}
    assert verif_infos_completes(complet)
    assert not verif_infos_completes({**complet, "key": None})
    assert not verif_infos_completes({**complet, "port": None})
