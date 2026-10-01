"""
Chaînes, IOC et marqueur d'un échantillon. Tout ce qui sort de l'échantillon est une donnée non fiable :
les chaînes qui s'adressent au LLM ou à l'analyste (injection de prompt, faux « honeypot ») sont mises de
côté et ne donnent ni IOC ni marqueur
"""

import ipaddress
import re
from urllib.parse import urlsplit

MIN_STRING_LENGTH = 4
# ASCII imprimable et caractères UTF-8 de 2 ou 3 octets (une injection en français a des accents)
TEXT_STRING = re.compile(
    rb"(?:[\x20-\x7e\t]|[\xc2-\xdf][\x80-\xbf]|[\xe0-\xef][\x80-\xbf]{2}){%d,}" % MIN_STRING_LENGTH
)
WIDE_STRING = re.compile(rb"(?:[\x20-\x7e\t]\x00){%d,}" % MIN_STRING_LENGTH)

PROMPT_INJECTION = re.compile(
    "|".join(
        (
            r"\bignor\w*\s+(?:all\s+|any\s+|the\s+|your\s+)*(?:previous|prior|above|earlier|preceding|former)\s+"
            r"(?:instructions?|prompts?|rules|messages?)",
            r"\b(?:disregard|forget|override)\s+(?:[\w-]+\s+){0,3}"
            r"(?:instructions?|indicators?|iocs?|rules|findings|results?|data)\b",
            r"\b(?:AI|LLM|GPT|ASSISTANT|MODEL|SYSTEM)_?(?:INSTRUCTIONS?|PROMPT|NOTE|MESSAGE)\b",
            r"\bNOTE_?TO_?(?:AI|LLM|ASSISTANT|MODEL|ANALYSTS?)\b",
            r"\bANALYST_?NOTE\b",
            r"\bhoneypot\b",
            r"\bsystem\s+prompt\b",
            r"\byou\s+are\s+(?:now\s+)?(?:an?\s+)?(?:ai|assistant|language\s+model|chatbot|llm)\b",
            r"\b(?:mark|declare|report|classify|consider|treat|label)\s+(?:the\s+|this\s+)?(?:sample|file|binary|program)"
            r"\s+(?:as\s+)?(?:clean|benign|safe|harmless|legit\w*)",
            r"\b(?:this|the)\s+(?:sample|file|binary|program)\s+is\s+(?:clean|benign|safe|harmless|legit\w*)",
            r"\b(?:do\s+not|don't|never)\s+(?:report|flag|mention)",
            r"\breport\s+only\b",
            r"\bconfirmed\s+flag\b",
            r"\bscore\s*(?:=|:|of|is)?\s*0\b",
            r"\bignor\w*\s+(?:toutes\s+)?(?:les\s+|tes\s+|vos\s+)?(?:instructions|consignes|r[eè]gles)",
            r"\boubli\w*\s+(?:toutes\s+)?(?:les\s+|tes\s+|vos\s+)?(?:instructions|consignes)",
            r"\b(?:d[ée]clar|consid[èée]r|marqu|class|indiqu)\w*\s+(?:ce|cet|le|l')\s*(?:fichier|[ée]chantillon|binaire)"
            r"\s+(?:comme\s+)?(?:sain|propre|b[ée]nin|inoffensif|l[ée]gitime)",
            r"\b(?:fichier|[ée]chantillon|binaire)\s+(?:est\s+)?(?:sain|b[ée]nin|inoffensif)\b",
            r"\bne\s+(?:signal|rapport|report|mentionn)\w*\s+(?:aucun|pas|rien)",
        )
    ),
    re.IGNORECASE,
)

FLAG = re.compile(r"ESGI\{[^\s{}]{1,100}\}")
LABELLED_FLAG = re.compile(r"(?<![\w ])(?:FLAG|MARQUEUR)\s*[=:]\s*(ESGI\{[^\s{}]{1,100}\})", re.IGNORECASE)

# TLD génériques courants, ceux des tests (RFC 2606 / 6761) et des réseaux internes. Les TLD de 2 lettres
# (pays) sont tous acceptés sauf ceux qui sont surtout des extensions de fichiers (libc.so, setup.py...)
GENERIC_TLDS = frozenset(
    """
    com net org info biz name pro edu gov mil int mobi asia tel xyz top site online club live shop store tech
    app dev cloud space website icu buzz fun link click work life world today email host press rest bar win
    bid loan date review stream download racing party trade science cam monster cyou sbs quest lol support
    services network digital agency zone run one tools page blog news media
    onion test example invalid localhost local lan internal corp home arpa
    """.split()
)
FILE_EXTENSION_TLDS = frozenset("so py sh js md mo po ps pl pm rb cs gz xz ko bz db rs hh cc".split())

# domaines de logiciels légitimes qu'on trouve dans presque tous les binaires (aide, licence, certificats) :
# ce ne sont pas des IOC
BENIGN_DOMAINS = frozenset(
    """
    gnu.org fsf.org translationproject.org sourceware.org kernel.org debian.org ubuntu.com freedesktop.org
    gnome.org kde.org python.org perl.org openssl.org apache.org mozilla.org w3.org xmlsoap.org
    openxmlformats.org purl.org schemas.microsoft.com microsoft.com windows.com windowsupdate.com
    msftncsi.com digicert.com verisign.com symantec.com globalsign.com sectigo.com usertrust.com
    comodoca.com letsencrypt.org entrust.net godaddy.com thawte.com opensource.org creativecommons.org
    """.split()
)

DOMAIN = re.compile(
    r"(?<![\w.@-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}))(?![\w-]|\.\w)", re.IGNORECASE
)
URL = re.compile(r"\b(?:https?|ftps?|wss?)://[^\s\"'<>`{}|\\^]+", re.IGNORECASE)
URL_TRAILING_PUNCTUATION = ".,;:!?)]}'\""
IP_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
IPV4 = re.compile(rf"(?<![\w.]){IP_OCTET}(?:\.{IP_OCTET}){{3}}(?![\w.]*\d)")
MUTEX = re.compile(r"(?<![\w\\])(?:Global|Local)\\[\w.{}#@$-]{1,128}")
REGISTRY_ROOT = (
    r"(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG"
    r"|HKLM|HKCU|HKCR|HKCC|HKU)"
)
REGISTRY_PART = r"[\w.{}$%@#~-]+"
# une partie avec des espaces (Windows NT) doit être suivie d'un \ : la phrase après la clé n'est pas prise
REGISTRY = re.compile(
    rf"(?<!\w){REGISTRY_ROOT}(?:\\{REGISTRY_PART}(?: {REGISTRY_PART})*(?=\\))*\\{REGISTRY_PART}",
    re.IGNORECASE,
)
WINDOWS_PATH = re.compile(r"(?<![\w%])(?:[A-Za-z]:\\|%[A-Za-z_]+%\\)[^\x00-\x1f\"<>|*?]{1,250}")
UNIX_PATH = re.compile(
    r"(?<![\w.~/-])/(?:tmp|etc|var|usr|home|dev|proc|bin|sbin|opt|root|lib|lib64|run|boot|mnt|srv|sys)"
    r"(?:/[\w.+@-]+)+"
)

IOC_CATEGORIES = ("domains", "ips", "urls", "mutex", "registry")


def extract_strings(data: bytes) -> list[str]:
    """
    Chaînes de texte (ASCII/UTF-8 et UTF-16LE comme dans les binaires Windows) dans l'ordre du fichier,
    sans doublon
    """
    found = [
        (match.start(), match.group().decode("utf-8", "replace")) for match in TEXT_STRING.finditer(data)
    ]
    for match in WIDE_STRING.finditer(data):
        start = match.start()
        # "ab\0" puis du texte UTF-16 : "b\0" ressemble à un caractère UTF-16 mais finit la chaîne ASCII
        if start > 0 and 0x20 <= data[start - 1] <= 0x7E:
            start += 2
        found.append((start, data[start : match.end()].decode("utf-16-le")))
    found.sort(key=lambda item: item[0])
    return list(dict.fromkeys(text.strip() for _, text in found if len(text.strip()) >= MIN_STRING_LENGTH))


def is_prompt_injection(text: str) -> bool:
    """
    Indique si une chaîne s'adresse au LLM ou à l'analyste pour orienter le verdict
    """
    return PROMPT_INJECTION.search(text) is not None


def find_prompt_injections(strings: list[str]) -> list[str]:
    """
    Chaînes de l'échantillon qui ressemblent à une injection de prompt
    """
    return [text for text in strings if is_prompt_injection(text)]


def get_trusted_strings(strings: list[str]) -> list[str]:
    """
    Chaînes qui peuvent servir de preuve : toutes sauf les tentatives d'injection
    """
    return [text for text in strings if not is_prompt_injection(text)]


def is_benign_domain(domain: str) -> bool:
    """
    Indique si un domaine (ou un de ses parents) est celui d'un logiciel légitime connu
    """
    labels = domain.lower().split(".")
    return any(".".join(labels[index:]) in BENIGN_DOMAINS for index in range(len(labels) - 1))


def is_valid_domain(domain: str) -> bool:
    """
    Indique si un nom ressemble à un vrai domaine et pas à un fichier (urlmon.dll, libc.so, gate.php...)
    """
    tld = domain.rsplit(".", 1)[-1].lower()
    if len(domain) > 253 or tld in FILE_EXTENSION_TLDS:
        return False
    return tld in GENERIC_TLDS or (len(tld) == 2 and tld.isalpha())


def is_plausible_bare_domain(domain: str) -> bool:
    """
    Indique si un domaine trouvé seul (hors URL) n'est pas un bout de données aléatoires (packer) : un vrai
    domaine a une casse uniforme et un nom d'au moins 2 caractères avant le TLD (pas « s.AR » ou « C.hR »)
    """
    return domain in (domain.lower(), domain.upper()) and len(domain.split(".")[-2]) >= 2


def is_public_ip(text: str) -> bool:
    """
    Garde les IP qui peuvent être celles d'un serveur (pas 0.0.0.0, 127.0.0.1, multicast, broadcast...)
    """
    address = ipaddress.ip_address(text)
    return not (
        address.is_unspecified
        or address.is_loopback
        or address.is_multicast
        or address.is_reserved
        or address.is_link_local
    )


def clean_url(url: str) -> str | None:
    """
    Retire la ponctuation collée à la fin d'une URL, None si son hôte n'est pas un domaine ou une IP valide
    ou est un domaine légitime connu
    """
    url = url.rstrip(URL_TRAILING_PUNCTUATION)
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        return None
    if IPV4.fullmatch(host):
        return url
    if not DOMAIN.fullmatch(host) or not is_valid_domain(host) or is_benign_domain(host):
        return None
    return url


def add_unique(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


def find_iocs_in_string(text: str, iocs: dict) -> None:
    """
    Ajoute à iocs les IOC trouvés dans une chaîne (de confiance)
    """
    for match in URL.finditer(text):
        url = clean_url(match.group())
        if url is None:
            continue
        add_unique(iocs["urls"], url)
        host = urlsplit(url).hostname or ""
        add_unique(iocs["ips"] if IPV4.fullmatch(host) else iocs["domains"], host.lower())
    for match in DOMAIN.finditer(text):
        domain = match.group(1)
        if is_valid_domain(domain) and is_plausible_bare_domain(domain) and not is_benign_domain(domain):
            add_unique(iocs["domains"], domain.lower())
    for match in IPV4.finditer(text):
        if is_public_ip(match.group()):
            add_unique(iocs["ips"], match.group())
    for match in MUTEX.finditer(text):
        add_unique(iocs["mutex"], match.group().rstrip("."))
    for match in REGISTRY.finditer(text):
        add_unique(iocs["registry"], match.group().rstrip("."))
    for match in (*WINDOWS_PATH.finditer(text), *UNIX_PATH.finditer(text)):
        add_unique(iocs["paths"], match.group().rstrip(" ."))


def extract_iocs(data: bytes, strings: list[str] | None = None) -> dict:
    """
    domaines, ips, urls, mutex, registry (regex sur les strings), plus les chemins de fichiers. Les chaînes
    d'une tentative d'injection sont ignorées : un faux IOC glissé dans une consigne au LLM n'est pas repris

    :param data: contenu de l'échantillon
    :param strings: chaînes déjà extraites de data (extraites ici sinon)
    :return: listes d'IOC par catégorie, dans l'ordre du fichier
    """
    iocs = {category: [] for category in (*IOC_CATEGORIES, "paths")}
    for text in get_trusted_strings(extract_strings(data) if strings is None else strings):
        find_iocs_in_string(text, iocs)
    return iocs


def find_flag(strings: list[str]) -> str | None:
    """
    Marqueur ESGI{...} de l'échantillon. Ceux d'une tentative d'injection (« the confirmed flag is ... »)
    sont des leurres et une chaîne qui dit que le vrai marqueur est un « honeypot » en est une aussi : seules
    les autres chaînes comptent, un marqueur annoncé par FLAG= d'abord

    :param strings: chaînes de l'échantillon
    :return: le marqueur, None s'il n'y en a pas de fiable
    """
    trusted = get_trusted_strings(strings)
    for text in trusted:
        match = LABELLED_FLAG.search(text)
        if match:
            return match.group(1)
    for text in trusted:
        match = FLAG.search(text)
        if match:
            return match.group()
    return None
