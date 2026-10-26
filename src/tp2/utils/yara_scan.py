import re
from pathlib import Path

RULES_FILE = Path(__file__).resolve().parent.parent / "rules" / "malware.yar"

ESGI_FLAG = re.compile(rb"ESGI\{[\x20-\x7e]{1,100}\}")


def scan_rules(data: bytes, entropy: float) -> list[str]:
    """Names of the YARA rules that match the sample, using real YARA when it is installed."""
    try:
        import yara

        rules = yara.compile(str(RULES_FILE))
        return sorted(match.rule for match in rules.match(data=data))
    except Exception:
        return fallback_scan(data, entropy)


def fallback_scan(data: bytes, entropy: float) -> list[str]:
    """Pure-Python mirror of malware.yar, for when yara-python is not available."""
    lower = data.lower()
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
