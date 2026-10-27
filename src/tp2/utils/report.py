import json
from pathlib import Path

from src.tp2.utils.config import logger

FONT = "Helvetica"


def ecrire_json(payload: str, path: Path) -> None:
    path.write_text(payload, encoding="utf-8")


def gen_rapport_triage(result: dict, out_dir: str, sample_name: str) -> Path:
    """Écrit <sample>.triage.json (attendu par le correcteur) et <sha256>.json dans out_dir.

    Produit aussi un PDF lisible (best-effort). Renvoie le chemin du .triage.json.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(result, indent=2, ensure_ascii=False)
    path_triage = out / f"{sample_name}.triage.json"
    ecrire_json(payload, path_triage)
    ecrire_json(payload, out / f"{result['sha256']}.json")
    try:
        _gen_pdf_triage(result, out / f"{sample_name}.triage.pdf")
    except Exception as error:
        logger.warning(f"PDF non généré : {error}")
    return path_triage


def _txt_pdf(valeur: str) -> str:
    return str(valeur).encode("latin-1", "replace").decode("latin-1")


def _titre_pdf(result: dict) -> str:
    return f"Triage - {result['family_guess']} (score {result['score']}/10)"


def _lignes_pdf(result: dict) -> list[str]:
    return [
        f"SHA-256 : {result['sha256']}",
        f"Type : {result['file_type']}",
        f"Entropie : {result['entropy']}",
        f"Drapeau : {result['flag']}",
        f"YARA : {', '.join(result['yara_matches']) or 'aucune'}",
        f"MITRE : {', '.join(result['mitre_attack']) or 'n/a'}",
        f"Résumé : {result['llm_summary']}",
    ]


def _gen_pdf_triage(result: dict, pdf_path: Path) -> None:
    from fpdf import FPDF

    pdf = FPDF()
    pdf.set_auto_page_break(True, margin=15)
    pdf.add_page()
    pdf.set_font(FONT, "B", 15)
    pdf.cell(0, 10, _txt_pdf(_titre_pdf(result)), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font(FONT, size=11)
    for ligne in _lignes_pdf(result):
        pdf.multi_cell(0, 7, _txt_pdf(ligne), new_x="LMARGIN", new_y="NEXT")
    pdf.output(str(pdf_path))
