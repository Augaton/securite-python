import hashlib
import math
import re
from collections import Counter
from pathlib import Path

from src.tp2.utils.yara_scan import scan_rules

FLAG_PATTERN = re.compile(rb"ESGI\{[\x21-\x7e]{1,100}\}")
URL_PATTERN = re.compile(rb"https?://[^\x00-\x20\"'<>\\)]+")
IPV4_PATTERN = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_PATTERN = re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
DOMAIN_PATTERN = re.compile(rb"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")
# TLDs we keep so file names like "libc.so" are not mistaken for domains ("test" = the C2's TLD)
DOMAIN_TLDS = {"com", "net", "org", "io", "ru", "cn", "xyz", "top", "test", "info",
               "biz", "online", "site", "gov", "edu", "co", "uk", "de", "fr"}
FILE_MAGICS = {b"\x7fELF": "ELF", b"MZ": "PE", b"\xca\xfe\xba\xbe": "Mach-O",
               b"\xcf\xfa\xed\xfe": "Mach-O", b"PK\x03\x04": "ZIP"}


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0 = uniform, ~8 = random/encrypted/packed)."""
    if not data:
        return 0.0
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in Counter(data).values())


def detect_file_type(data: bytes) -> str:
    for magic, name in FILE_MAGICS.items():
        if data.startswith(magic):
            return name
    return "data"


def valid_ipv4(ip: str) -> bool:
    return all(octet.isdigit() and int(octet) <= 255 for octet in ip.split("."))


def host_of(url: str) -> str:
    return url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]


def extract_iocs(data: bytes) -> dict:
    """URLs, IPv4, domains and emails found in the sample's printable strings."""
    urls = sorted({m.decode("latin-1") for m in URL_PATTERN.findall(data)})
    emails = sorted({m.decode("latin-1") for m in EMAIL_PATTERN.findall(data)})
    ips = sorted({m.decode() for m in IPV4_PATTERN.findall(data) if valid_ipv4(m.decode())})

    domains = {host_of(url) for url in urls} | {email.split("@", 1)[1] for email in emails}
    for match in DOMAIN_PATTERN.findall(data):
        domain = match.decode("latin-1")
        if domain.rsplit(".", 1)[-1].lower() in DOMAIN_TLDS:
            domains.add(domain)
    return {"urls": urls, "ipv4": ips, "domains": sorted(domains), "emails": emails}


def find_flag(data: bytes) -> str | None:
    """The real ESGI{...} marker, skipping the decoy flags planted to mislead."""
    for match in FLAG_PATTERN.findall(data):
        flag = match.decode("latin-1")
        if "decoy" not in flag.lower():
            return flag
    return None


def triage(path: Path) -> dict:
    data = path.read_bytes()
    entropy = shannon_entropy(data)
    return {
        "file": path.name,
        "size": len(data),
        "file_type": detect_file_type(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "entropy": round(entropy, 4),
        "packed": entropy >= 7.0,
        "iocs": extract_iocs(data),
        "yara": scan_rules(data, entropy),
        "flag": find_flag(data),
    }
