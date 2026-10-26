FAMILY_SIGNS = [
    ("keylog", "keylogger"),
    ("backdoor", "backdoor"),
    ("reverse_shell", "backdoor"),
    ("dropper", "dropper"),
    ("download", "dropper"),
    ("ransom", "ransomware"),
    ("packed", "packer"),
    ("high_entropy", "packer"),
]


def _has_network(iocs: dict) -> bool:
    return bool(iocs["urls"] or iocs["ips"] or iocs["domains"])


def guess_family(yara_matches: list[str], iocs: dict) -> str:
    """Famille probable, déduite des règles YARA (et de la présence d'un C2)."""
    joined = " ".join(yara_matches).lower()
    for key, family in FAMILY_SIGNS:
        if key in joined:
            return family
    return "backdoor" if _has_network(iocs) else "unknown"


def map_mitre(yara_matches: list[str], iocs: dict, metadata: dict) -> list[str]:
    """Techniques MITRE ATT&CK déduites des détections."""
    joined = " ".join(yara_matches).lower()
    techniques = set()
    if _has_network(iocs):
        techniques.add("T1071")  # Application Layer Protocol (C2)
    if "keylog" in joined:
        techniques.add("T1056.001")  # Input Capture: Keylogging
    if "dropper" in joined or "download" in joined:
        techniques.add("T1105")  # Ingress Tool Transfer
    if metadata["entropy"] >= 7.0 or "entropy" in joined or "packed" in joined:
        techniques.add("T1027")  # Obfuscated Files or Information
    if "backdoor" in joined or "reverse_shell" in joined or "shell" in joined:
        techniques.add("T1059")  # Command and Scripting Interpreter
    if iocs["registry"]:
        techniques.add("T1547")  # Boot or Logon Autostart Execution
    return sorted(techniques)


def compute_score(yara_matches: list[str], iocs: dict, metadata: dict) -> int:
    """Score 0-10 déterministe, fondé sur les règles YARA et les IOC (jamais sur le LLM seul)."""
    score = 0
    if _has_network(iocs):
        score += 4
    behaviour = [match for match in yara_matches if "entropy" not in match.lower()]
    score += 2 * len(behaviour)
    if metadata["entropy"] >= 7.0:
        score += 2
    return max(0, min(score, 10))


def build_features(metadata: dict, iocs: dict, yara_matches: list[str], imports: list[str]) -> dict:
    """Résumé structuré des features extraites (jamais le binaire brut) pour le LLM."""
    return {
        "file_type": metadata["file_type"],
        "entropy": metadata["entropy"],
        "yara_matches": yara_matches,
        "iocs": iocs,
        "imports": imports[:40],
    }


def deterministic_summary(family: str, score: int, yara_matches: list[str], iocs: dict) -> str:
    """Résumé lisible calculé localement (utilisé tel quel si le LLM est indisponible)."""
    network = iocs["urls"] + iocs["ips"] + iocs["domains"]
    return (
        f"Échantillon classé {family} (score {score}/10). "
        f"Règles YARA : {', '.join(yara_matches) or 'aucune'}. "
        f"Indicateurs réseau : {', '.join(network[:5]) or 'aucun'}."
    )
