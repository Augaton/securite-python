import re
from html.parser import HTMLParser
from urllib.parse import urljoin

import requests

from .captcha import Captcha
from .config import logger
from .fuzzer import trouver_ep_cache

FLAG_RE = re.compile(r"ESGI\{[^}]*\}")
# host:port — IP ou nom d'hote suivi d'un port
HOSTPORT_RE = re.compile(r"\b([A-Za-z0-9_.\-]+):(\d{2,5})\b")
# champs nommes explicitement dans le texte / le JSON de la page
HOST_FIELD_RE = re.compile(r"host[\"'\s:=]+([A-Za-z0-9_.\-]+)", re.IGNORECASE)
PORT_FIELD_RE = re.compile(r"port[\"'\s:=]+(\d{2,5})", re.IGNORECASE)
KEY_FIELD_RE = re.compile(r"(?:key|cl[eé])[\"'\s:=]+([A-Za-z0-9+/=_\-]{3,})", re.IGNORECASE)

# noms de champ a essayer si le formulaire n'est pas analysable
_FALLBACK_FIELDS = ("captcha", "answer", "code", "solution", "text", "input")


def _chercher_regex(regex: re.Pattern, texte: str, groupe: int = 0) -> str | None:
    m = regex.search(texte)
    return m.group(groupe) if m else None


def verif_infos_completes(data: dict) -> bool:
    return bool(data.get("flag1") and data.get("host") and data.get("port") and data.get("key"))


class _PageParser(HTMLParser):
    """Repere les <img> et le premier <form> (action, methode, champs)."""

    def __init__(self):
        super().__init__()
        self.images: list[str] = []
        self.form_action: str | None = None
        self.form_method = "post"
        self.fields: list[str] = []
        self._in_form = False

    def _ajout_img(self, src: str) -> None:
        self.images.append(src)

    def _ouvrir_form(self, a: dict) -> None:
        self._in_form = True
        self.form_action = a.get("action", "")
        self.form_method = (a.get("method") or "post").lower()

    def _ajout_champ(self, a: dict) -> None:
        name = a.get("name")
        if name and a.get("type") not in ("submit", "hidden"):
            self.fields.append(name)

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "img" and a.get("src"):
            self._ajout_img(a["src"])
        elif tag == "form" and self.form_action is None:
            self._ouvrir_form(a)
        elif tag in ("input", "textarea") and self._in_form:
            self._ajout_champ(a)

    def handle_endtag(self, tag):
        if tag == "form":
            self._in_form = False


class WebPhase:
    """Phase web du TP3 : fuzzing -> captcha -> page revelant flag1, host:port et cle."""

    def __init__(self, target: str, wordlist=None, max_attempts: int = 15):
        self.target = target.rstrip("/")
        self.wordlist = wordlist
        self.max_attempts = max_attempts
        self.session = requests.Session()
        self.endpoint: str | None = None

    def derouler_phase_web(self) -> dict:
        """Deroule la phase web et renvoie {flag1, host, port, key}."""
        self.endpoint, _ = trouver_ep_cache(self.target, self.session, self.wordlist)
        for essai in range(1, self.max_attempts + 1):
            data = self._tenter_essai(essai)
            if data is not None:
                return data
        raise RuntimeError(f"captcha non resolu apres {self.max_attempts} essais")

    def _lire_page_captcha(self) -> _PageParser:
        page = self.session.get(self.endpoint, timeout=10)
        parser = _PageParser()
        parser.feed(page.text)
        return parser

    def _tenter_essai(self, essai: int) -> dict | None:
        """Un essai : lit la page, resout le captcha, envoie la reponse ; None si refuse."""
        parser = self._lire_page_captcha()
        reponse = self._resoudre_captcha(parser)
        if not reponse:
            return None
        data = self._extraire_infos_page(self._envoyer_reponse_captcha(parser, reponse))
        if verif_infos_completes(data):
            logger.info(f"captcha franchi a l'essai {essai}")
            return data
        logger.info(f"essai {essai} : captcha refuse ou page incomplete (reponse '{reponse}')")
        return None

    def _resoudre_captcha(self, parser: _PageParser) -> str:
        url_img = self._trouver_img_captcha(parser)
        return Captcha(url_img, self.session).solve()

    def _trouver_img_captcha(self, parser: _PageParser) -> str:
        """URL de l'image du captcha : premier <img> de la page, sinon le chemin usuel "captcha"."""
        src = parser.images[0] if parser.images else "captcha"
        return urljoin(self.endpoint + "/", src)

    def _envoyer_reponse_captcha(self, parser: _PageParser, reponse: str) -> requests.Response:
        """Renvoie la reponse du captcha au formulaire (POST/GET), cookies conserves."""
        action = urljoin(self.endpoint + "/", parser.form_action or "")
        champs = parser.fields or list(_FALLBACK_FIELDS)
        payload = {name: reponse for name in champs}
        if parser.form_method == "get":
            return self.session.get(action, params=payload, timeout=10)
        return self.session.post(action, data=payload, timeout=10)

    @staticmethod
    def _extraire_depuis_json(resp: requests.Response) -> dict:
        data: dict = {}
        try:
            payload = resp.json()
            if isinstance(payload, dict):
                data["flag1"] = payload.get("flag") or payload.get("flag1")
                data["host"] = payload.get("host")
                port = payload.get("port")
                data["port"] = int(port) if port is not None else None
                data["key"] = payload.get("key")
        except ValueError:
            pass
        return data

    def _completer_depuis_txt(self, data: dict, texte: str) -> None:
        """Remplit ce que le JSON n'a pas donne en cherchant dans le texte de la page."""
        if not data.get("flag1"):
            data["flag1"] = _chercher_regex(FLAG_RE, texte)
        if not data.get("key"):
            data["key"] = _chercher_regex(KEY_FIELD_RE, texte, 1)
        if not data.get("host") or not data.get("port"):
            host, port = self._extraire_host_port(texte)
            data["host"] = data.get("host") or host
            data["port"] = data.get("port") or port

    def _extraire_infos_page(self, resp: requests.Response) -> dict:
        """Extrait flag1, host, port et cle du JSON ou du texte de la reponse."""
        data = self._extraire_depuis_json(resp)
        self._completer_depuis_txt(data, resp.text)
        logger.info(
            f"page revelee -> flag1={data.get('flag1')} host={data.get('host')} "
            f"port={data.get('port')} key={data.get('key')}"
        )
        return data

    @staticmethod
    def _extraire_host_port(texte: str) -> tuple[str | None, int | None]:
        hm = HOST_FIELD_RE.search(texte)
        pm = PORT_FIELD_RE.search(texte)
        if hm and pm:
            return hm.group(1), int(pm.group(1))
        m = HOSTPORT_RE.search(texte)
        if m:
            return m.group(1), int(m.group(2))
        return None, None
