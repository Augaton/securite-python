from pathlib import Path

from src.tp2.utils.analysis import shannon_entropy

DEFAULT_RULES_DIR = Path(__file__).resolve().parents[3] / "rules"


def yara_scan(data: bytes, rules_dir: str | None = None) -> list[str]:
    """Noms des règles YARA déclenchées par le fichier.

    Compile chaque .yar du dossier donné (une règle cassée n'empêche pas les autres).
    Repli en Python pur sur nos propres règles si yara-python est absent.
    """
    directory = Path(rules_dir) if rules_dir else DEFAULT_RULES_DIR
    try:
        import yara

        matches: set[str] = set()
        rule_files = sorted(directory.glob("**/*.yar"))
        if not rule_files:
            return _fallback(data)
        for rule_file in rule_files:
            try:
                compiled = yara.compile(str(rule_file))
                matches.update(match.rule for match in compiled.match(data=data))
            except Exception:
                continue
        return sorted(matches)
    except Exception:
        return _fallback(data)


def _fallback(data: bytes) -> list[str]:
    """Reproduit nos règles rules/esgi_rules.yar quand yara-python n'est pas disponible."""
    lower = data.lower()
    matches = []
    if b"/gate.php" in data and (b"c2-" in data or b".example.test" in data):
        matches.append("ESGI_C2_HTTP_Beacon")
    if b"GetAsyncKeyState" in data or b"keylog" in lower:
        matches.append("ESGI_Keylogger_Behavior")
    if b"backdoor" in lower or b"reverse shell" in lower or b"/bin/sh" in data:
        matches.append("ESGI_Reverse_Shell_Backdoor")
    if shannon_entropy(data) >= 7.0:
        matches.append("ESGI_High_Entropy_Payload")
    return sorted(matches)
