import hashlib
import math
from collections import Counter
from pathlib import Path

from tp2.utils.config import logger
from tp2.utils.iocs import extract_iocs, extract_strings, find_flag, find_prompt_injections

ENTROPY_DECIMALS = 2

# type de fichier quand libmagic n'est pas disponible, d'après les premiers octets
MAGIC_NUMBERS = (
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE32 executable (MS-DOS header)"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit"),
    (b"%PDF", "PDF document"),
    (b"PK\x03\x04", "Zip archive data"),
    (b"#!", "script text executable"),
)


def shannon_entropy(data: bytes) -> float:
    """
    Entropie de Shannon en bits par octet : 0 pour un octet répété, 8 pour des données aléatoires
    (compressées ou chiffrées, souvent un packer)
    """
    if not data:
        return 0.0
    freq = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def get_file_type(data: bytes) -> str:
    """
    Type du fichier avec libmagic (comme la commande file), d'après les premiers octets sinon
    """
    try:
        import magic

        return magic.from_buffer(data)
    except (ImportError, OSError) as error:
        logger.warning(f"libmagic indisponible ({error}), type deviné d'après les premiers octets")
    except Exception as error:  # magic.MagicException sur un fichier que libmagic ne sait pas lire
        logger.warning(f"libmagic n'a pas pu lire le fichier : {error}")
    return next((name for magic_number, name in MAGIC_NUMBERS if data.startswith(magic_number)), "data")


def get_file_metadata(data: bytes) -> dict:
    """
    sha256, md5, taille, type de fichier, entropie de Shannon
    """
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "size": len(data),
        "entropy": round(shannon_entropy(data), ENTROPY_DECIMALS),
        "file_type": get_file_type(data),
    }


def get_binary_format(binary) -> str | None:
    """
    Format d'un binaire lu par lief (PE, ELF ou Mach-O)
    """
    import lief

    for name in ("PE", "ELF", "MachO"):
        module = getattr(lief, name, None)
        if module is not None and isinstance(binary, module.Binary):
            return name
    return None


def get_names(items) -> list[str]:
    """
    Noms (sans doublon ni nom vide) d'une liste de fonctions ou de bibliothèques lief
    """
    names = (item if isinstance(item, str) else getattr(item, "name", "") for item in items)
    return list(dict.fromkeys(name for name in names if name))


def parse_binary(path: str) -> dict:
    """
    imports / exports / sections via lief (si PE/ELF), avec la taille et l'entropie de l'overlay (les données
    ajoutées après la fin du binaire, souvent la charge utile d'un dropper)
    """
    info = {"format": None, "imports": [], "exports": [], "libraries": [], "sections": [], "overlay": {}}
    try:
        import lief
    except ImportError:
        logger.warning("lief n'est pas installé : pas d'analyse des imports et des sections")
        return info

    lief.logging.disable()
    try:
        binary = lief.parse(str(path))
    except Exception as error:  # lief lève des erreurs variées sur un binaire malformé
        logger.warning(f"lief n'a pas pu lire {path} : {error}")
        return info
    if binary is None:
        return info

    info["format"] = get_binary_format(binary)
    info["imports"] = get_names(binary.imported_functions)
    info["exports"] = get_names(binary.exported_functions)
    info["libraries"] = get_names(binary.libraries)
    info["sections"] = [
        {"name": section.name, "size": section.size, "entropy": round(section.entropy, ENTROPY_DECIMALS)}
        for section in binary.sections
        if section.name
    ]
    overlay = bytes(getattr(binary, "overlay", b""))
    if overlay:
        info["overlay"] = {
            "offset": Path(path).stat().st_size - len(overlay),
            "size": len(overlay),
            "entropy": round(shannon_entropy(overlay), ENTROPY_DECIMALS),
        }
    return info


class Sample:
    def __init__(self, path: str) -> None:
        self.path = path
        self.name = Path(path).name
        self.data = Path(path).read_bytes()
        self.strings = extract_strings(self.data)

    def get_file_metadata(self) -> dict:
        """sha256, md5, taille, type de fichier, entropie de Shannon."""
        return get_file_metadata(self.data)

    def shannon_entropy(self) -> float:
        return shannon_entropy(self.data)

    def extract_iocs(self) -> dict:
        """domaines, ips, urls, mutex, registry (regex sur les strings)."""
        return extract_iocs(self.data, self.strings)

    def parse_binary(self) -> dict:
        """imports / sections via lief (si PE/ELF)."""
        return parse_binary(self.path)

    def get_prompt_injections(self) -> list[str]:
        """
        Chaînes qui s'adressent au LLM ou à l'analyste pour fausser le verdict
        """
        return find_prompt_injections(self.strings)

    def get_flag(self) -> str | None:
        """
        Marqueur ESGI{...} de l'échantillon, sans ceux des tentatives d'injection
        """
        return find_flag(self.strings)
