from pathlib import Path

from src.tp2.utils import analysis, verdict
from src.tp2.utils.config import logger
from src.tp2.utils.llm import LLMClient, llm_triage
from src.tp2.utils.scanner import scan_yara


def fusion_mitre_llm(mitre: list[str], llm: dict) -> list[str]:
    return sorted(set(mitre) | {technique for technique in llm["mitre_attack"] if isinstance(technique, str)})


def resume_llm(llm: dict) -> str:
    return " | LLM : " + str(llm["famille"]).replace("\n", " ")[:120]


def constr_resultat_base(meta: dict, iocs: dict, imports: list[str], yara_matches: list[str]) -> dict:
    return {
        "sha256": meta["sha256"],
        "md5": meta["md5"],
        "size": meta["size"],
        "entropy": meta["entropy"],
        "file_type": meta["file_type"],
        "iocs": iocs,
        "imports": imports,
        "yara_matches": yara_matches,
    }


def triage_echantillon(path: str, rules_dir: str | None, client: LLMClient) -> dict:
    """Analyse un échantillon et renvoie le dict de résultat au format attendu par le correcteur."""
    data = Path(path).read_bytes()
    logger.info(f"Triage de {path} ({len(data)} octets)")

    meta = analysis.recup_meta_fichier(data)
    iocs = analysis.extraire_iocs(data)
    binaire = analysis.parser_binaire_lief(str(path))
    yara_matches = scan_yara(data, rules_dir)
    flag = analysis.trouver_vrai_flag(data)

    # verdict déterministe : ne dépend ni du réseau ni du LLM (résiste à l'injection de prompt)
    famille = verdict.deviner_famille(yara_matches, iocs)
    mitre = verdict.mapper_mitre(yara_matches, iocs, meta)
    score = verdict.calc_score(yara_matches, iocs, meta)
    resume = verdict.gen_resume_local(famille, score, yara_matches, iocs)

    # le LLM n'enrichit que le texte et les techniques ; il ne touche jamais au score ni au flag
    features = verdict.constr_features_llm(meta, iocs, yara_matches, binaire["imports"])
    llm = llm_triage(features, client)
    if llm:
        mitre = fusion_mitre_llm(mitre, llm)
        resume += resume_llm(llm)

    resultat = constr_resultat_base(meta, iocs, binaire["imports"], yara_matches)
    resultat.update(family_guess=famille, mitre_attack=mitre, llm_summary=resume, score=score, flag=flag)
    return resultat
