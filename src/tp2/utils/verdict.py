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


def _a_ioc_reseau(iocs: dict) -> bool:
    return bool(iocs["urls"] or iocs["ips"] or iocs["domains"])


def _joindre_regles(yara_matches: list[str]) -> str:
    return " ".join(yara_matches).lower()


def deviner_famille(yara_matches: list[str], iocs: dict) -> str:
    """Famille probable, déduite des règles YARA (et de la présence d'un C2)."""
    regles = _joindre_regles(yara_matches)
    for mot_cle, famille in FAMILY_SIGNS:
        if mot_cle in regles:
            return famille
    return "backdoor" if _a_ioc_reseau(iocs) else "unknown"


def _mitre_depuis_regles(regles: str) -> set[str]:
    techniques = set()
    if "keylog" in regles:
        techniques.add("T1056.001")  # Input Capture: Keylogging
    if "dropper" in regles or "download" in regles:
        techniques.add("T1105")  # Ingress Tool Transfer
    if "backdoor" in regles or "reverse_shell" in regles or "shell" in regles:
        techniques.add("T1059")  # Command and Scripting Interpreter
    return techniques


def mapper_mitre(yara_matches: list[str], iocs: dict, metadata: dict) -> list[str]:
    """Techniques MITRE ATT&CK déduites des détections."""
    regles = _joindre_regles(yara_matches)
    techniques = _mitre_depuis_regles(regles)
    if _a_ioc_reseau(iocs):
        techniques.add("T1071")  # Application Layer Protocol (C2)
    if metadata["entropy"] >= 7.0 or "entropy" in regles or "packed" in regles:
        techniques.add("T1027")  # Obfuscated Files or Information
    if iocs["registry"]:
        techniques.add("T1547")  # Boot or Logon Autostart Execution
    return sorted(techniques)


def _nb_regles_comportement(yara_matches: list[str]) -> int:
    """Règles qui décrivent un comportement (l'entropie seule est comptée à part)."""
    return len([match for match in yara_matches if "entropy" not in match.lower()])


def calc_score(yara_matches: list[str], iocs: dict, metadata: dict) -> int:
    """Score 0-10 déterministe, fondé sur les règles YARA et les IOC (jamais sur le LLM seul)."""
    score = 0
    if _a_ioc_reseau(iocs):
        score += 4
    score += 2 * _nb_regles_comportement(yara_matches)
    if metadata["entropy"] >= 7.0:
        score += 2
    return max(0, min(score, 10))


def constr_features_llm(metadata: dict, iocs: dict, yara_matches: list[str], imports: list[str]) -> dict:
    """Résumé structuré des features extraites (jamais le binaire brut) pour le LLM."""
    return {
        "file_type": metadata["file_type"],
        "entropy": metadata["entropy"],
        "yara_matches": yara_matches,
        "iocs": iocs,
        "imports": imports[:40],
    }


def gen_resume_local(famille: str, score: int, yara_matches: list[str], iocs: dict) -> str:
    """Résumé lisible calculé localement (utilisé tel quel si le LLM est indisponible)."""
    ioc_reseau = iocs["urls"] + iocs["ips"] + iocs["domains"]
    return (
        f"Échantillon classé {famille} (score {score}/10). "
        f"Règles YARA : {', '.join(yara_matches) or 'aucune'}. "
        f"Indicateurs réseau : {', '.join(ioc_reseau[:5]) or 'aucun'}."
    )
