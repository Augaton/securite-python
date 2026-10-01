import json
from datetime import datetime, timezone
from pathlib import Path

from fpdf import FPDF
from fpdf.fonts import FontFace

from tp2.utils.config import logger
from tp2.utils.iocs import IOC_CATEGORIES

FONT = "Helvetica"
MARGIN_MM = 18
GREY_TEXT = (82, 81, 78)
HEADINGS_STYLE = FontFace(emphasis="BOLD", fill_color=(240, 239, 236))
# couleur du score : vert (sain), orange (suspect), rouge (malveillant)
SCORE_COLORS = ((4, (46, 139, 87)), (7, (230, 140, 20)), (11, (200, 40, 40)))
SCORE_BAR_WIDTH_MM = 80
SCORE_BAR_HEIGHT_MM = 5
IOC_LABELS = {
    "domains": "Domaine",
    "ips": "IP",
    "urls": "URL",
    "mutex": "Mutex",
    "registry": "Registre",
    "paths": "Chemin",
}
MAX_IMPORTS_SHOWN = 80
MAX_INJECTION_LENGTH = 300
MIN_SECTION_SPACE_MM = 30


def to_pdf_text(text) -> str:
    """
    Texte affichable par les polices de base de fpdf (latin-1), sans caractères de contrôle venus de
    l'échantillon
    """
    text = "".join(char if char.isprintable() or char == "\n" else " " for char in str(text))
    return text.encode("latin-1", "replace").decode("latin-1")


def to_grader_json(result: dict) -> dict:
    """
    Résultat au format exact demandé par le correcteur
    """
    return {
        "sha256": result["sha256"],
        "md5": result["md5"],
        "size": result["size"],
        "entropy": result["entropy"],
        "file_type": result["file_type"],
        "iocs": {category: list(result["iocs"][category]) for category in IOC_CATEGORIES},
        "imports": result["imports"],
        "yara_matches": result["yara_matches"],
        "family_guess": result["family_guess"],
        "mitre_attack": result["mitre_attack"],
        "llm_summary": result["llm_summary"],
        "score": result["score"],
        "flag": result["flag"],
    }


def get_score_color(score: int) -> tuple[int, int, int]:
    return next(color for limit, color in SCORE_COLORS if score < limit)


class Report:
    def __init__(self, result: dict) -> None:
        self.result = result
        self.title = "Rapport de triage malware"

    def generate_json(self, out_json: str) -> None:
        """Fichier JSON lisible."""
        with Path(out_json).open("w", encoding="utf-8") as json_file:
            json.dump(to_grader_json(self.result), json_file, indent=2, ensure_ascii=False)
        logger.info(f"Résultat pour le correcteur enregistré dans {out_json}")

    def generate_pdf(self, out_pdf: str) -> None:
        """Rapport PDF lisible (fpdf2)."""
        pdf = FPDF()
        pdf.set_margins(MARGIN_MM, MARGIN_MM)
        pdf.set_auto_page_break(True, margin=MARGIN_MM)
        pdf.add_page()
        self.add_title(pdf)
        self.add_verdict(pdf)
        self.add_metadata(pdf)
        self.add_iocs(pdf)
        self.add_yara(pdf)
        self.add_capabilities(pdf)
        self.add_binary(pdf)
        self.add_injections(pdf)
        pdf.output(out_pdf)
        logger.info(f"Rapport enregistré dans {out_pdf}")

    def add_title(self, pdf: FPDF) -> None:
        pdf.set_font(FONT, "B", 18)
        pdf.cell(0, 10, self.title, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font(FONT, size=10)
        pdf.set_text_color(*GREY_TEXT)
        date = datetime.now(timezone.utc).astimezone().strftime("%d/%m/%Y à %H:%M")
        subtitle = f"{self.result['file_name']} - généré le {date}"
        pdf.multi_cell(0, 6, to_pdf_text(subtitle), new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0)
        pdf.ln(4)

    @staticmethod
    def add_section(pdf: FPDF, title: str) -> None:
        """
        Ajoute le titre d'une partie, sur la page suivante s'il resterait seul en bas de page
        """
        if pdf.get_y() > pdf.h - MARGIN_MM - MIN_SECTION_SPACE_MM:
            pdf.add_page()
        pdf.ln(4)
        pdf.set_font(FONT, "B", 13)
        pdf.cell(0, 8, to_pdf_text(title), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font(FONT, size=10)

    @staticmethod
    def add_text(pdf: FPDF, text: str, grey: bool = False) -> None:
        if grey:
            pdf.set_text_color(*GREY_TEXT)
        pdf.multi_cell(0, 5, to_pdf_text(text), align="L", new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0)

    @staticmethod
    def add_table(pdf: FPDF, headings: tuple[str, ...] | None, rows: list[tuple], col_widths: tuple) -> None:
        """
        Ajoute un tableau, sans ligne de titres si headings est None (tableau libellé / valeur)
        """
        with pdf.table(
            col_widths=col_widths,
            text_align="LEFT",
            borders_layout="HORIZONTAL_LINES",
            headings_style=HEADINGS_STYLE,
            first_row_as_headings=headings is not None,
            line_height=5,
        ) as table:
            if headings is not None:
                table.row(headings)
            for row in rows:
                table.row(tuple(to_pdf_text(cell) for cell in row))

    def add_score_bar(self, pdf: FPDF) -> None:
        """
        Barre du score sur 10, colorée selon la gravité
        """
        score = self.result["score"]
        pdf.set_font(FONT, "B", 12)
        pdf.cell(32, SCORE_BAR_HEIGHT_MM + 2, f"Score : {score}/10")
        x, y = pdf.get_x(), pdf.get_y() + 1
        pdf.set_fill_color(225, 224, 220)
        pdf.rect(x, y, SCORE_BAR_WIDTH_MM, SCORE_BAR_HEIGHT_MM, style="F")
        pdf.set_fill_color(*get_score_color(score))
        pdf.rect(x, y, SCORE_BAR_WIDTH_MM * score / 10, SCORE_BAR_HEIGHT_MM, style="F")
        # les tableaux de fpdf2 remplissent une ligne sur deux avec cette couleur
        pdf.set_fill_color(255)
        pdf.ln(SCORE_BAR_HEIGHT_MM + 4)
        pdf.set_font(FONT, size=10)

    def add_verdict(self, pdf: FPDF) -> None:
        result = self.result
        self.add_section(pdf, "Verdict")
        self.add_score_bar(pdf)
        rows = [
            ("Famille", result["family_guess"]),
            ("Famille selon le LLM", (result["llm"]["verdict"] or {}).get("family", "pas de verdict")),
            ("MITRE ATT&CK", ", ".join(result["mitre_attack"]) or "aucune technique"),
            ("Marqueur", result["flag"] or "aucun"),
            ("Score sans LLM", f"{result['heuristic_score']}/10 ({result['heuristic_family']})"),
            ("Source du verdict", result["llm"]["note"]),
        ]
        self.add_table(pdf, None, rows, (1, 3.2))
        pdf.ln(2)
        self.add_text(pdf, result["llm_summary"])

    def add_metadata(self, pdf: FPDF) -> None:
        result = self.result
        self.add_section(pdf, "Empreintes")
        rows = [
            ("SHA-256", result["sha256"]),
            ("MD5", result["md5"]),
            ("Taille", f"{result['size']} octets"),
            ("Type", result["file_type"]),
            ("Entropie", f"{result['entropy']} bits/octet (8 = compressé ou chiffré)"),
        ]
        self.add_table(pdf, None, rows, (1, 3.2))

    def add_iocs(self, pdf: FPDF) -> None:
        self.add_section(pdf, "Indicateurs de compromission (IOC)")
        iocs = {**self.result["iocs"], "paths": self.result["paths"]}
        rows = [(IOC_LABELS[category], value) for category in IOC_LABELS for value in iocs[category]]
        if not rows:
            self.add_text(pdf, "Aucun IOC trouvé.")
            return
        self.add_table(pdf, ("Type", "Valeur"), rows, (1, 4.2))

    def add_yara(self, pdf: FPDF) -> None:
        self.add_section(pdf, "Règles YARA déclenchées")
        details = self.result["yara_details"]
        if not details:
            self.add_text(pdf, "Aucune règle déclenchée.")
            return
        rows = [(detail["rule"], detail["source"], detail["description"]) for detail in details]
        self.add_table(pdf, ("Règle", "Source", "Description"), rows, (2, 1.3, 3.5))

    def add_capabilities(self, pdf: FPDF) -> None:
        self.add_section(pdf, "Capacités")
        capabilities = self.result["capabilities"]
        if not capabilities:
            self.add_text(pdf, "Aucune capacité suspecte trouvée.")
            return
        rows = [(name, ", ".join(evidence[:4])) for name, evidence in capabilities.items()]
        self.add_table(pdf, ("Capacité", "Preuves"), rows, (1.4, 4))

    def add_binary(self, pdf: FPDF) -> None:
        binary = self.result["binary"]
        self.add_section(pdf, "Binaire")
        if binary["format"] is None:
            self.add_text(pdf, "Ni PE ni ELF : pas d'imports ni de sections.")
            return
        overlay = binary["overlay"]
        overlay_text = (
            f"{overlay['size']} octets à partir de l'offset {overlay['offset']}, entropie {overlay['entropy']}"
            if overlay
            else "aucun"
        )
        imports = self.result["imports"]
        shown_imports = ", ".join(imports[:MAX_IMPORTS_SHOWN]) + (
            " ..." if len(imports) > MAX_IMPORTS_SHOWN else ""
        )
        rows = [
            ("Format", binary["format"]),
            ("Bibliothèques", ", ".join(binary["libraries"]) or "aucune"),
            ("Imports", shown_imports or "aucun"),
            ("Exports", ", ".join(binary["exports"]) or "aucun"),
            ("Overlay", overlay_text),
        ]
        self.add_table(pdf, None, rows, (1, 4.2))
        if binary["sections"]:
            pdf.ln(2)
            rows = [(section["name"], section["size"], section["entropy"]) for section in binary["sections"]]
            self.add_table(pdf, ("Section", "Taille", "Entropie"), rows, (2, 1, 1))

    def add_injections(self, pdf: FPDF) -> None:
        injections = self.result["prompt_injections"]
        self.add_section(pdf, "Tentatives d'injection de prompt")
        if not injections:
            self.add_text(pdf, "Aucune.")
            return
        self.add_text(
            pdf,
            "Texte du fichier qui s'adresse au LLM ou à l'analyste. Il n'est pas envoyé au LLM et ne compte ni "
            "pour les IOC, ni pour le marqueur, ni pour baisser le score.",
            grey=True,
        )
        pdf.set_font("Courier", size=8)
        for text in injections:
            shown = text if len(text) <= MAX_INJECTION_LENGTH else text[:MAX_INJECTION_LENGTH] + "..."
            pdf.ln(1)
            pdf.multi_cell(0, 4, to_pdf_text(shown), align="L", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font(FONT, size=10)


def generate_report(result: dict, out_dir: str, pdf: bool = True) -> Path:
    """
    Écrit <sha256>.json (format du correcteur) et <sha256>.pdf dans out_dir. Un échec du pdf ne doit pas
    empêcher le JSON d'être lu par le correcteur

    :return: chemin du JSON
    """
    report = Report(result)
    json_path = Path(out_dir) / f"{result['sha256']}.json"
    report.generate_json(str(json_path))
    if pdf:
        try:
            report.generate_pdf(str(json_path.with_suffix(".pdf")))
        except Exception as error:  # fpdf2 peut échouer sur un texte inattendu : le JSON est déjà écrit
            logger.warning(f"Rapport PDF de {result['file_name']} non généré : {error}")
    return json_path
