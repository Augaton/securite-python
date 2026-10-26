import json
from pathlib import Path

from src.tp2.utils.config import logger

FONT = "Helvetica"


def generate_report(result: dict, out_dir: str) -> Path:
    """Écrit le JSON machine <sha256>.json dans out_dir (et un PDF lisible, best-effort). Renvoie le JSON."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / f"{result['sha256']}.json"
    json_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    try:
        _generate_pdf(result, out / f"{result['sha256']}.pdf")
    except Exception as error:
        logger.warning(f"PDF non généré : {error}")
    return json_path


def _generate_pdf(result: dict, pdf_path: Path) -> None:
    from fpdf import FPDF

    def text(value: str) -> str:
        return str(value).encode("latin-1", "replace").decode("latin-1")

    pdf = FPDF()
    pdf.set_auto_page_break(True, margin=15)
    pdf.add_page()
    pdf.set_font(FONT, "B", 15)
    pdf.cell(0, 10, text(f"Triage - {result['family_guess']} (score {result['score']}/10)"),
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_font(FONT, size=11)
    for line in (
        f"SHA-256 : {result['sha256']}",
        f"Type : {result['file_type']}",
        f"Entropie : {result['entropy']}",
        f"Drapeau : {result['flag']}",
        f"YARA : {', '.join(result['yara_matches']) or 'aucune'}",
        f"MITRE : {', '.join(result['mitre_attack']) or 'n/a'}",
        f"Résumé : {result['llm_summary']}",
    ):
        pdf.multi_cell(0, 7, text(line), new_x="LMARGIN", new_y="NEXT")
    pdf.output(str(pdf_path))
