from functools import lru_cache
from pathlib import Path

from tp2.utils.config import logger
from tp2.utils.rules import CUSTOM_RULES

DEFAULT_RULES_PATH = "rules"
RULE_EXTENSIONS = (".yar", ".yara", ".rule", ".rules")
MATCH_TIMEOUT = 60
CUSTOM_RULES_SOURCE = "règles perso"
# variables que des règles peuvent utiliser (comme avec yara -d) : sans elles leur compilation échoue
EXTERNALS = {"filename": "", "filepath": "", "extension": "", "filetype": ""}


def find_rule_files(rules_path: str | None) -> list[Path]:
    """
    Fichiers de règles YARA : le fichier donné, ou les .yar/.yara d'un dossier (et de ses sous-dossiers)

    :param rules_path: fichier ou dossier de règles
    :return: chemins des fichiers de règles, triés
    """
    if not rules_path:
        return []
    path = Path(rules_path)
    if path.is_file():
        return [path]
    if not path.is_dir():
        logger.warning(f"Règles YARA introuvables : {rules_path} (seules nos règles sont utilisées)")
        return []
    return sorted(
        file
        for file in path.rglob("*")
        if file.is_file() and file.suffix.lower() in RULE_EXTENSIONS and not file.name.startswith(".")
    )


class YaraScanner:
    def __init__(self, rules_path: str | None = DEFAULT_RULES_PATH) -> None:
        self.rules_path = rules_path
        self.rules = self.load_rules()

    def load_rules(self) -> list[tuple[str, object]]:
        """
        Compile les règles du cours (chaque fichier à part : un fichier invalide n'empêche pas les autres) puis
        les nôtres

        :return: couples (source des règles, règles compilées)
        """
        try:
            import yara
        except ImportError:
            logger.error("yara-python n'est pas installé : pas d'analyse YARA")
            return []
        rules = []
        for rule_file in find_rule_files(self.rules_path):
            try:
                rules.append((rule_file.name, yara.compile(filepath=str(rule_file), externals=EXTERNALS)))
            except yara.Error as error:
                logger.warning(f"Règles YARA ignorées ({rule_file}) : {error}")
        rules.append((CUSTOM_RULES_SOURCE, yara.compile(source=CUSTOM_RULES, externals=EXTERNALS)))
        logger.info(f"Règles YARA chargées : {', '.join(source for source, _ in rules)}")
        return rules

    def scan_details(self, data: bytes, filename: str = "") -> list[dict]:
        """
        Règles YARA déclenchées, avec leur source et leur description

        :param data: contenu de l'échantillon
        :param filename: nom de l'échantillon (pour les règles qui utilisent la variable filename)
        :return: une entrée par règle, sans doublon de nom
        """
        externals = {**EXTERNALS, "filename": Path(filename).name, "filepath": filename}
        externals["extension"] = Path(filename).suffix.lstrip(".")
        matches = {}
        for source, rules in self.rules:
            try:
                found = rules.match(data=data, externals=externals, timeout=MATCH_TIMEOUT)
            except Exception as error:  # yara.Error ou yara.TimeoutError
                logger.warning(f"Analyse YARA ({source}) interrompue : {error}")
                continue
            for match in found:
                matches.setdefault(
                    match.rule,
                    {
                        "rule": match.rule,
                        "source": source,
                        "description": str(match.meta.get("description", "")),
                    },
                )
        return list(matches.values())

    def scan(self, data: bytes, filename: str = "") -> list[str]:
        """Noms des règles YARA déclenchées."""
        return [match["rule"] for match in self.scan_details(data, filename)]


@lru_cache(maxsize=8)
def get_scanner(rules_path: str | None = DEFAULT_RULES_PATH) -> YaraScanner:
    """
    Scanner (règles compilées une seule fois) pour un dossier de règles
    """
    return YaraScanner(rules_path)


def yara_scan(data: bytes, rules_path: str | None = DEFAULT_RULES_PATH) -> list[str]:
    """
    Noms des règles YARA déclenchées : celles du cours (rules_path) et les nôtres
    """
    return get_scanner(rules_path).scan(data)
