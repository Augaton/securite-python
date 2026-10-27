from pathlib import Path

from src.tp2.utils.analysis import calc_entropie_shannon

DEFAULT_RULES_DIR = Path(__file__).resolve().parents[3] / "rules"


def lister_regles_yar(dossier: Path) -> list[Path]:
    return sorted(dossier.glob("**/*.yar"))


def _matcher_regle_yar(yara, fichier_regle: Path, data: bytes) -> set[str]:
    """Règles déclenchées par un .yar ; un fichier qui ne compile pas ne casse pas les autres."""
    try:
        regles = yara.compile(str(fichier_regle))
        return {match.rule for match in regles.match(data=data)}
    except Exception:
        return set()


def scan_yara(data: bytes, rules_dir: str | None = None) -> list[str]:
    """Noms des règles YARA déclenchées par le fichier.

    Compile chaque .yar du dossier donné (une règle cassée n'empêche pas les autres).
    Repli en Python pur sur nos propres règles si yara-python est absent.
    """
    dossier = Path(rules_dir) if rules_dir else DEFAULT_RULES_DIR
    try:
        import yara

        fichiers_regles = lister_regles_yar(dossier)
        if not fichiers_regles:
            return _scan_repli_python(data)
        matches: set[str] = set()
        for fichier_regle in fichiers_regles:
            matches |= _matcher_regle_yar(yara, fichier_regle, data)
        return sorted(matches)
    except Exception:
        return _scan_repli_python(data)


def _scan_repli_python(data: bytes) -> list[str]:
    """Reproduit nos règles rules/esgi_rules.yar quand yara-python n'est pas disponible."""
    lower = data.lower()
    matches = []
    if b"/gate.php" in data and (b"c2-" in data or b".example.test" in data):
        matches.append("ESGI_C2_HTTP_Beacon")
    if b"GetAsyncKeyState" in data or b"keylog" in lower:
        matches.append("ESGI_Keylogger_Behavior")
    if b"backdoor" in lower or b"reverse shell" in lower or b"/bin/sh" in data:
        matches.append("ESGI_Reverse_Shell_Backdoor")
    if calc_entropie_shannon(data) >= 7.0:
        matches.append("ESGI_High_Entropy_Payload")
    return sorted(matches)
