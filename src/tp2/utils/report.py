import json
from pathlib import Path

from fpdf import FPDF

FONT = "Helvetica"


def _pdf_text(text: str) -> str:
    """Remplace par "?" les caractères hors latin-1 (polices de base de fpdf)."""
    return str(text).encode("latin-1", "replace").decode("latin-1")


class Report:
    def __init__(self, result: dict) -> None:
        self.result = result

    def generate_json(self, out_json: str) -> None:
        """Fichier JSON lisible."""
        Path(out_json).write_text(json.dumps(self.result, indent=2, ensure_ascii=False), encoding="utf-8")

    def generate_pdf(self, out_pdf: str) -> None:
        """Rapport PDF lisible (fpdf2)."""
        meta = self.result.get("meta", {})
        pdf = FPDF()
        pdf.set_auto_page_break(True, margin=15)
        pdf.add_page()

        pdf.set_font(FONT, "B", 16)
        pdf.cell(0, 10, _pdf_text(f"Triage - {self.result.get('file', '')}"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

        pdf.set_font(FONT, size=11)
        lines = [
            f"SHA-256 : {meta.get('sha256', '')}",
            f"MD5 : {meta.get('md5', '')}",
            f"Taille : {meta.get('size', '')} octets",
            f"Type : {meta.get('file_type', '')}",
            f"Entropie : {meta.get('entropy', '')} (packé : {meta.get('packed', False)})",
            f"Drapeau : {self.result.get('flag')}",
            f"Règles YARA : {', '.join(self.result.get('yara', [])) or 'aucune'}",
        ]
        for line in lines:
            pdf.multi_cell(0, 7, _pdf_text(line), new_x="LMARGIN", new_y="NEXT")

        self._add_iocs(pdf)
        pdf.output(out_pdf)

    def _add_iocs(self, pdf: FPDF) -> None:
        iocs = self.result.get("iocs", {})
        pdf.ln(3)
        pdf.set_font(FONT, "B", 12)
        pdf.cell(0, 8, "IOC", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font(FONT, size=10)
        for label, values in iocs.items():
            pdf.multi_cell(0, 6, _pdf_text(f"{label} : {', '.join(values) or '-'}"), new_x="LMARGIN", new_y="NEXT")
