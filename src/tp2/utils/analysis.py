import hashlib
import math
import re
from collections import Counter

FLAG_PATTERN = re.compile(rb"ESGI\{[\x21-\x7e]{1,100}\}")
URL_PATTERN = re.compile(rb"https?://[^\x00-\x20\"'<>\\)]+")
IPV4_PATTERN = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_PATTERN = re.compile(rb"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
MUTEX_PATTERN = re.compile(rb"(?:Global|Local)\\[^\s\x00\"']{1,80}")
REGISTRY_PATTERN = re.compile(rb"HK(?:LM|CU|CR|U|CC)\\[^\s\x00\"']{1,160}")
DOMAIN_TLDS = {
    "com",
    "net",
    "org",
    "io",
    "ru",
    "cn",
    "xyz",
    "top",
    "test",
    "info",
    "biz",
    "online",
    "site",
    "gov",
    "edu",
    "co",
    "uk",
    "de",
    "fr",
    "su",
    "pw",
}


MAGIC_BYTES = {
    b"\x7fELF": "ELF binary",
    b"MZ": "PE32 executable",
    b"\xca\xfe\xba\xbe": "Mach-O binary",
    b"PK\x03\x04": "Zip archive",
}


def calc_entropie_shannon(data: bytes) -> float:
    """Entropie de Shannon en bits par octet (0 = uniforme, ~8 = aléatoire/chiffré/packé)."""
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def detect_type_octets_magiques(data: bytes) -> str:
    for octets_magiques, nom in MAGIC_BYTES.items():
        if data.startswith(octets_magiques):
            return nom
    return "data"


def detect_type_fichier(data: bytes) -> str:
    """Type de fichier via python-magic, avec repli sur les octets magiques."""
    try:
        import magic

        return magic.from_buffer(data)
    except Exception:
        return detect_type_octets_magiques(data)


def recup_meta_fichier(data: bytes) -> dict:
    """SHA-256, MD5, taille, type de fichier et entropie de Shannon."""
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "size": len(data),
        "file_type": detect_type_fichier(data),
        "entropy": round(calc_entropie_shannon(data), 2),
    }


def _decoder_trier(lst_matchs: list[bytes]) -> list[str]:
    return sorted({match.decode("latin-1") for match in lst_matchs})


def extraire_urls(data: bytes) -> list[str]:
    return _decoder_trier(URL_PATTERN.findall(data))


def extraire_ips(data: bytes) -> list[str]:
    return [ip for ip in _decoder_trier(IPV4_PATTERN.findall(data)) if _verif_ipv4(ip)]


def extraire_domaines(data: bytes, urls: list[str]) -> list[str]:
    """Hôtes des URLs, plus les noms de domaine nus dont le TLD est connu."""
    domaines = {_recup_host_url(url) for url in urls}
    for match in DOMAIN_PATTERN.findall(data):
        domaine = match.decode("latin-1")
        if domaine.rsplit(".", 1)[-1].lower() in DOMAIN_TLDS:
            domaines.add(domaine)
    return sorted(domaines)


def extraire_iocs(data: bytes) -> dict:
    """Domaines, IP, URLs, mutex et clés de registre trouvés dans les chaînes du fichier."""
    urls = extraire_urls(data)
    return {
        "domains": extraire_domaines(data, urls),
        "ips": extraire_ips(data),
        "urls": urls,
        "mutex": _decoder_trier(MUTEX_PATTERN.findall(data)),
        "registry": _decoder_trier(REGISTRY_PATTERN.findall(data)),
    }


def trouver_vrai_flag(data: bytes) -> str | None:
    """Le vrai marqueur ESGI{...}, en ignorant les faux drapeaux (decoy) plantés pour tromper."""
    for match in FLAG_PATTERN.findall(data):
        flag = match.decode("latin-1")
        if "decoy" not in flag.lower():
            return flag
    return None


def _recup_noms_fonctions(binaire, attribut: str) -> list[str]:
    """Noms des fonctions importées / exportées ; liste vide si lief ne sait pas les lire."""
    try:
        return [fonction.name for fonction in getattr(binaire, attribut) if fonction.name]
    except Exception:
        return []


def parser_binaire_lief(path: str) -> dict:
    """Imports, exports et sections via lief (PE/ELF) ; listes vides si lief indisponible ou format inconnu."""
    vide = {"imports": [], "exports": [], "sections": []}
    try:
        import lief

        binaire = lief.parse(path)
        if binaire is None:
            return vide
        return {
            "imports": _recup_noms_fonctions(binaire, "imported_functions"),
            "exports": _recup_noms_fonctions(binaire, "exported_functions"),
            "sections": [section.name for section in binaire.sections if section.name],
        }
    except Exception:
        return vide


def _verif_ipv4(ip: str) -> bool:
    return all(octet.isdigit() and int(octet) <= 255 for octet in ip.split("."))


def _recup_host_url(url: str) -> str:
    return url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
