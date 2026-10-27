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


class _PageParser(HTMLParser):
    """Repere les <img> et le premier <form> (action, methode, champs)."""

    def __init__(self):
        super().__init__()
        self.images: list[str] = []
        self.form_action: str | None = None
        self.form_method = "post"
        self.fields: list[str] = []
        self._in_form = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "img" and a.get("src"):
            self.images.append(a["src"])
        elif tag == "form" and self.form_action is None:
            self._in_form = True
            self.form_action = a.get("action", "")
            self.form_method = (a.get("method") or "post").lower()
        elif tag in ("input", "textarea") and self._in_form:
            name = a.get("name")
            if name and a.get("type") not in ("submit", "hidden"):
                self.fields.append(name)

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

    def run(self) -> dict:
        """Deroule la phase web et renvoie {flag1, host, port, key}."""
        self.endpoint, _ = trouver_ep_cache(self.target, self.session, self.wordlist)

        for attempt in range(1, self.max_attempts + 1):
            page = self.session.get(self.endpoint, timeout=10)
            parser = _PageParser()
            parser.feed(page.text)

            answer = self._solve_captcha(parser)
            if not answer:
                continue

            result = self._submit(parser, answer)
            data = self._extract(result)
            if data.get("flag1") and data.get("host") and data.get("port") and data.get("key"):
                logger.info(f"captcha franchi a l'essai {attempt}")
                return data
            logger.info(f"essai {attempt} : captcha refuse ou page incomplete (reponse '{answer}')")

        raise RuntimeError(f"captcha non resolu apres {self.max_attempts} essais")

    def _solve_captcha(self, parser: _PageParser) -> str:
        img_url = self._find_captcha_image(parser)
        return Captcha(img_url, self.session).solve()

    def _find_captcha_image(self, parser: _PageParser) -> str:
        """URL de l'image du captcha : <img> de la page, sinon chemins usuels."""
        for src in parser.images:
            return urljoin(self.endpoint + "/", src)
        for guess in ("captcha", "captcha.png", "image", "img"):
            return urljoin(self.endpoint + "/", guess)
        return self.endpoint

    def _submit(self, parser: _PageParser, answer: str) -> requests.Response:
        """Renvoie la reponse du captcha au formulaire (POST/GET), cookies conserves."""
        action = urljoin(self.endpoint + "/", parser.form_action or "")
        fields = parser.fields or list(_FALLBACK_FIELDS)
        payload = {name: answer for name in fields}
        if parser.form_method == "get":
            return self.session.get(action, params=payload, timeout=10)
        return self.session.post(action, data=payload, timeout=10)

    def _extract(self, resp: requests.Response) -> dict:
        """Extrait flag1, host, port et cle du JSON ou du texte de la reponse."""
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

        text = resp.text
        if not data.get("flag1"):
            m = FLAG_RE.search(text)
            data["flag1"] = m.group() if m else None
        if not data.get("key"):
            m = KEY_FIELD_RE.search(text)
            data["key"] = m.group(1) if m else None
        if not data.get("host") or not data.get("port"):
            host, port = self._extract_hostport(text)
            data["host"] = data.get("host") or host
            data["port"] = data.get("port") or port

        logger.info(
            f"page revelee -> flag1={data.get('flag1')} host={data.get('host')} "
            f"port={data.get('port')} key={data.get('key')}"
        )
        return data

    @staticmethod
    def _extract_hostport(text: str) -> tuple[str | None, int | None]:
        hm = HOST_FIELD_RE.search(text)
        pm = PORT_FIELD_RE.search(text)
        if hm and pm:
            return hm.group(1), int(pm.group(1))
        m = HOSTPORT_RE.search(text)
        if m:
            return m.group(1), int(m.group(2))
        return None, None
