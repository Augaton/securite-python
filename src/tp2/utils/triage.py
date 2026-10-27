from pathlib import Path

from src.tp2.utils import analysis, verdict
from src.tp2.utils.config import logger
from src.tp2.utils.llm import LLMClient, llm_triage
from src.tp2.utils.scanner import yara_scan


def triage_sample(path: str, rules_dir: str | None, client: LLMClient) -> dict:
    """Analyse un échantillon et renvoie le dict de résultat au format attendu par le correcteur."""
    data = Path(path).read_bytes()
    logger.info(f"Triage de {path} ({len(data)} octets)")

    meta = analysis.recup_meta_fichier(data)
    iocs = analysis.extraire_iocs(data)
    binary = analysis.parser_binaire_lief(str(path))
    yara_matches = yara_scan(data, rules_dir)
    flag = analysis.trouver_vrai_flag(data)

    # verdict déterministe : ne dépend ni du réseau ni du LLM (résiste à l'injection de prompt)
    family = verdict.guess_family(yara_matches, iocs)
    mitre = verdict.map_mitre(yara_matches, iocs, meta)
    score = verdict.compute_score(yara_matches, iocs, meta)
    summary = verdict.deterministic_summary(family, score, yara_matches, iocs)

    # le LLM n'enrichit que le texte et les techniques ; il ne touche jamais au score ni au flag
    features = verdict.build_features(meta, iocs, yara_matches, binary["imports"])
    llm = llm_triage(features, client)
    if llm:
        mitre = sorted(set(mitre) | {t for t in llm["mitre_attack"] if isinstance(t, str)})
        summary += " | LLM : " + str(llm["famille"]).replace("\n", " ")[:120]

    return {
        "sha256": meta["sha256"],
        "md5": meta["md5"],
        "size": meta["size"],
        "entropy": meta["entropy"],
        "file_type": meta["file_type"],
        "iocs": iocs,
        "imports": binary["imports"],
        "yara_matches": yara_matches,
        "family_guess": family,
        "mitre_attack": mitre,
        "llm_summary": summary,
        "score": score,
        "flag": flag,
    }
