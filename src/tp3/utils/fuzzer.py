import uuid
from pathlib import Path

import requests

from .config import logger

# wordlist embarquee : l'outil tourne sans Internet, on l'ouvre par un chemin
# relatif au code (pas au repertoire courant, qui est vide a la correction).
DEFAULT_WORDLIST = Path(__file__).resolve().parent.parent / "wordlist.txt"


def load_words(path: Path | str | None = None) -> list[str]:
    """Lit la wordlist, ignore lignes vides et commentaires, normalise les slashs."""
    path = Path(path) if path else DEFAULT_WORDLIST
    words: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        word = line.strip().strip("/")
        if word and not word.startswith("#"):
            words.append(word)
    return words


def _baseline_not_found(base: str, session: requests.Session) -> tuple[int, int]:
    """Sonde un chemin presque surement absent pour apprendre la signature du 404."""
    url = f"{base}/{uuid.uuid4().hex}"
    resp = session.get(url, timeout=10, allow_redirects=False)
    return resp.status_code, len(resp.content)


def _looks_like_hit(resp: requests.Response, nf_status: int, nf_len: int) -> bool:
    """Un endpoint existe si sa reponse se distingue nettement de la reference 404."""
    if resp.status_code in (200, 301, 302, 401, 403) and resp.status_code != nf_status:
        return True
    # certains serveurs repondent 200 a tout : on separe alors par la taille du corps
    return resp.status_code == nf_status == 200 and abs(len(resp.content) - nf_len) > 64


def find_hidden_endpoint(
    base_url: str,
    session: requests.Session | None = None,
    wordlist: Path | str | None = None,
) -> tuple[str, requests.Response]:
    """Fuzze la wordlist sur la cible et renvoie (url, reponse) du premier endpoint cache."""
    base = base_url.rstrip("/")
    session = session or requests.Session()
    words = load_words(wordlist)
    nf_status, nf_len = _baseline_not_found(base, session)
    logger.info(f"reference 'introuvable' : status={nf_status} taille={nf_len}")

    for word in words:
        for path in (word, f"{word}/"):
            url = f"{base}/{path}"
            try:
                resp = session.get(url, timeout=10, allow_redirects=False)
            except requests.RequestException:
                continue
            if _looks_like_hit(resp, nf_status, nf_len):
                logger.info(f"endpoint cache trouve : {url} (status {resp.status_code})")
                return url, resp

    raise RuntimeError("aucun endpoint cache trouve dans la wordlist")
