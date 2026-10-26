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


def shannon_entropy(data: bytes) -> float:
    """Entropie de Shannon en bits par octet (0 = uniforme, ~8 = aléatoire/chiffré/packé)."""
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def detect_file_type(data: bytes) -> str:
    """Type de fichier via python-magic, avec repli sur les octets magiques."""
    try:
        import magic

        return magic.from_buffer(data)
    except Exception:
        for magic_bytes, name in {
            b"\x7fELF": "ELF binary",
            b"MZ": "PE32 executable",
            b"\xca\xfe\xba\xbe": "Mach-O binary",
            b"PK\x03\x04": "Zip archive",
        }.items():
            if data.startswith(magic_bytes):
                return name
        return "data"


def get_file_metadata(data: bytes) -> dict:
    """SHA-256, MD5, taille, type de fichier et entropie de Shannon."""
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "size": len(data),
        "file_type": detect_file_type(data),
        "entropy": round(shannon_entropy(data), 2),
    }


def extract_iocs(data: bytes) -> dict:
    """Domaines, IP, URLs, mutex et clés de registre trouvés dans les chaînes du fichier."""
    urls = sorted({m.decode("latin-1") for m in URL_PATTERN.findall(data)})
    ips = sorted({m.decode() for m in IPV4_PATTERN.findall(data) if _valid_ipv4(m.decode())})
    mutex = sorted({m.decode("latin-1") for m in MUTEX_PATTERN.findall(data)})
    registry = sorted({m.decode("latin-1") for m in REGISTRY_PATTERN.findall(data)})

    domains = {_host_of(url) for url in urls}
    for match in DOMAIN_PATTERN.findall(data):
        domain = match.decode("latin-1")
        if domain.rsplit(".", 1)[-1].lower() in DOMAIN_TLDS:
            domains.add(domain)
    return {"domains": sorted(domains), "ips": ips, "urls": urls, "mutex": mutex, "registry": registry}


def find_flag(data: bytes) -> str | None:
    """Le vrai marqueur ESGI{...}, en ignorant les faux drapeaux (decoy) plantés pour tromper."""
    for match in FLAG_PATTERN.findall(data):
        flag = match.decode("latin-1")
        if "decoy" not in flag.lower():
            return flag
    return None


def parse_binary(path: str) -> dict:
    """Imports, exports et sections via lief (PE/ELF) ; listes vides si lief indisponible ou format inconnu."""
    empty = {"imports": [], "exports": [], "sections": []}
    try:
        import lief

        binary = lief.parse(path)
        if binary is None:
            return empty
        imports, exports = [], []
        try:
            imports = [f.name for f in binary.imported_functions if f.name]
        except Exception:
            imports = []
        try:
            exports = [f.name for f in binary.exported_functions if f.name]
        except Exception:
            exports = []
        sections = [s.name for s in binary.sections if s.name]
        return {"imports": imports, "exports": exports, "sections": sections}
    except Exception:
        return empty


def _valid_ipv4(ip: str) -> bool:
    return all(octet.isdigit() and int(octet) <= 255 for octet in ip.split("."))


def _host_of(url: str) -> str:
    return url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
