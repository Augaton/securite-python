import hashlib
import math
import re
from collections import Counter
from pathlib import Path

FLAG_PATTERN = re.compile(rb"ESGI\{[\x21-\x7e]{1,100}\}")
URL_PATTERN = re.compile(rb"https?://[^\x00-\x20\"'<>\\)]+")
IPV4_PATTERN = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_PATTERN = re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
DOMAIN_PATTERN = re.compile(rb"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")
# TLD gardés pour ne pas prendre un nom de fichier comme "libc.so" pour un domaine ("test" = TLD du C2)
DOMAIN_TLDS = {"com", "net", "org", "io", "ru", "cn", "xyz", "top", "test", "info",
               "biz", "online", "site", "gov", "edu", "co", "uk", "de", "fr"}
FILE_MAGICS = {b"\x7fELF": "ELF", b"MZ": "PE", b"\xca\xfe\xba\xbe": "Mach-O",
               b"\xcf\xfa\xed\xfe": "Mach-O", b"PK\x03\x04": "ZIP"}


class Sample:
    def __init__(self, path: str) -> None:
        self.path = path
        self.data = Path(path).read_bytes()

    def get_file_metadata(self) -> dict:
        """sha256, md5, taille, type de fichier, entropie de Shannon."""
        entropy = self.shannon_entropy()
        return {
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "md5": hashlib.md5(self.data).hexdigest(),
            "size": len(self.data),
            "file_type": self.detect_file_type(),
            "entropy": round(entropy, 4),
            "packed": entropy >= 7.0,
        }

    def shannon_entropy(self) -> float:
        if not self.data:
            return 0.0
        freq = Counter(self.data)
        n = len(self.data)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    def detect_file_type(self) -> str:
        try:
            import magic

            return magic.from_buffer(self.data)
        except Exception:
            for magic_bytes, name in FILE_MAGICS.items():
                if self.data.startswith(magic_bytes):
                    return name
            return "data"

    def extract_iocs(self) -> dict:
        """URL, IPv4, domaines et emails trouvés dans les chaînes imprimables."""
        urls = sorted({m.decode("latin-1") for m in URL_PATTERN.findall(self.data)})
        emails = sorted({m.decode("latin-1") for m in EMAIL_PATTERN.findall(self.data)})
        ips = sorted({m.decode() for m in IPV4_PATTERN.findall(self.data) if _valid_ipv4(m.decode())})

        domains = {_host_of(url) for url in urls} | {email.split("@", 1)[1] for email in emails}
        for match in DOMAIN_PATTERN.findall(self.data):
            domain = match.decode("latin-1")
            if domain.rsplit(".", 1)[-1].lower() in DOMAIN_TLDS:
                domains.add(domain)
        return {"urls": urls, "ipv4": ips, "domains": sorted(domains), "emails": emails}

    def parse_binary(self) -> dict:
        """Format, sections et imports via lief (si ELF/PE) ; {} sinon ou si lief indisponible."""
        try:
            import lief

            binary = lief.parse(self.path)
            if binary is None:
                return {}
            sections = [section.name for section in binary.sections]
            try:
                imports = [function.name for function in binary.imported_functions]
            except Exception:
                imports = []
            return {
                "format": str(binary.format).rsplit(".", 1)[-1],
                "sections": sections[:50],
                "imports": imports[:100],
            }
        except Exception:
            return {}

    def find_flag(self) -> str | None:
        """Le vrai marqueur ESGI{...}, en ignorant les faux drapeaux (decoy)."""
        for match in FLAG_PATTERN.findall(self.data):
            flag = match.decode("latin-1")
            if "decoy" not in flag.lower():
                return flag
        return None


def _valid_ipv4(ip: str) -> bool:
    return all(octet.isdigit() and int(octet) <= 255 for octet in ip.split("."))


def _host_of(url: str) -> str:
    return url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
