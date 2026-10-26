import math
import re
from collections import Counter
from pathlib import Path

RULES_FILE = Path(__file__).resolve().parent.parent / "rules" / "course_rules.yar"
ESGI_FLAG = re.compile(rb"ESGI\{[\x20-\x7e]{1,100}\}")


class YaraScanner:
    def __init__(self, rules_path: str | None = None) -> None:
        self.rules_path = str(rules_path or RULES_FILE)

    def scan(self, data: bytes) -> list[str]:
        """Noms des règles YARA déclenchées (vrai YARA s'il est installé, sinon repli Python)."""
        try:
            import yara

            rules = yara.compile(self.rules_path)
            return sorted(match.rule for match in rules.match(data=data))
        except Exception:
            return self._fallback(data)

    @staticmethod
    def _fallback(data: bytes) -> list[str]:
        """Reproduit course_rules.yar quand yara-python n'est pas disponible."""
        lower = data.lower()
        entropy = _entropy(data)
        matches = []
        if b"/gate.php" in data and (b"c2-" in data or b".example.test" in data):
            matches.append("suspicious_c2_http")
        if b"GetAsyncKeyState" in data or b"keylog" in lower:
            matches.append("keylogger_behavior")
        if b"backdoor" in lower or b"reverse shell" in lower:
            matches.append("backdoor_behavior")
        if b"dropper" in lower:
            matches.append("dropper_behavior")
        if entropy >= 7.0:
            matches.append("high_entropy_packed")
        if ESGI_FLAG.search(data):
            matches.append("embedded_esgi_flag")
        return sorted(matches)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())
