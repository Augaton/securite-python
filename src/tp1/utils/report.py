import json
from datetime import datetime, timezone
from pathlib import Path

from fpdf import FPDF
from fpdf.fonts import FontFace

from src.tp1.utils.capture import Capture
from src.tp1.utils.config import logger
from src.tp1.utils.graph import enreg_graph_svg
from src.tp1.utils.lib import formater_part_pct

FONT = "Helvetica"
MARGIN_MM = 20
GREY_TEXT = (82, 81, 78)
HEADINGS_STYLE = FontFace(emphasis="BOLD", fill_color=(240, 239, 236))
BAR_COLOR = (42, 120, 214)
LABEL_WIDTH_MM = 45
VALUE_WIDTH_MM = 22
BAR_HEIGHT_MM = 5
BAR_GAP_MM = 1.5
MAX_BARS = 25  # au-delà le graphique ne tient plus sur une page (le tableau, lui, garde tout)


def txt_pdf(texte: str) -> str:
    """Remplace par "?" les caractères que les polices de base de fpdf (latin-1) ne savent pas écrire."""
    return str(texte).encode("latin-1", "replace").decode("latin-1")


def ecrire_paragraphe(pdf: FPDF, texte: str) -> None:
    pdf.multi_cell(0, 6, txt_pdf(texte), new_x="LMARGIN", new_y="NEXT")


def recup_date_now() -> str:
    return datetime.now(timezone.utc).astimezone().strftime("%d/%m/%Y à %H:%M")


class Report:
    def __init__(self, capture: Capture, filename: str, summary: str):
        self.capture = capture
        self.filename = filename
        self.title = "Rapport de capture réseau"
        self.summary = summary
        self.array = []
        self.graph = ""

    def concat_report(self) -> FPDF:
        pdf = FPDF()
        pdf.set_margins(MARGIN_MM, MARGIN_MM)
        pdf.set_auto_page_break(True, margin=MARGIN_MM)
        pdf.add_page()
        self.ajout_titre(pdf)

        self.ajout_section(pdf, "Résumé")
        ecrire_paragraphe(pdf, self.summary)
        pdf.ln(6)

        self.ajout_section(pdf, "Répartition des paquets par protocole")
        self.ajout_tableau_protos(pdf)
        pdf.ln(6)

        self.ajout_section(pdf, "Légitimité du trafic")
        self.ajout_attaques(pdf)
        pdf.ln(6)

        self.ajout_graph(pdf)
        return pdf

    def ajout_titre(self, pdf: FPDF) -> None:
        pdf.set_font(FONT, "B", 18)
        pdf.cell(0, 10, self.title, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font(FONT, size=10)
        pdf.set_text_color(*GREY_TEXT)
        sous_titre = f"Généré le {recup_date_now()} - {self.capture.recup_source()}"
        pdf.cell(0, 6, txt_pdf(sous_titre), new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0)
        pdf.ln(6)

    @staticmethod
    def ajout_section(pdf: FPDF, titre: str) -> None:
        pdf.set_font(FONT, "B", 13)
        pdf.cell(0, 8, titre, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font(FONT, size=11)

    def ajout_tableau_protos(self, pdf: FPDF) -> None:
        total = sum(nb for _, nb in self.array)
        with pdf.table(
            col_widths=(3, 1.6, 1.8, 3.6),
            text_align=("LEFT", "RIGHT", "RIGHT", "LEFT"),
            borders_layout="HORIZONTAL_LINES",
            headings_style=HEADINGS_STYLE,
            line_height=7,
        ) as table:
            table.row(("Protocole", "Paquets", "Part du trafic", "Trafic"))
            for proto, nb in self.array:
                table.row((proto, str(nb), formater_part_pct(nb, total), self.recup_legitimite(proto)))
            table.row(("Total", str(total), formater_part_pct(total, total), ""))

    def recup_legitimite(self, proto: str) -> str:
        noms_attaques = [attaque.name for attaque in self.capture.attacks if attaque.protocol == proto]
        if not noms_attaques:
            return "Légitime"
        return "Illégitime : " + ", ".join(noms_attaques)

    @staticmethod
    def ajout_tableau_attaques(pdf: FPDF, lst_attaques: list) -> None:
        with pdf.table(
            col_widths=(2.2, 1.8, 2.4, 3, 4.6),
            text_align="LEFT",
            borders_layout="HORIZONTAL_LINES",
            headings_style=HEADINGS_STYLE,
            line_height=6,
        ) as table:
            table.row(("Attaque", "Protocole", "IP attaquant", "MAC attaquant", "Détails"))
            for attaque in lst_attaques:
                cellules = (
                    attaque.name,
                    attaque.protocol,
                    attaque.attacker_ip,
                    attaque.attacker_mac,
                    attaque.details,
                )
                table.row(tuple(txt_pdf(cellule) for cellule in cellules))

    def ajout_flag(self, pdf: FPDF) -> None:
        if self.capture.flag is not None:
            pdf.ln(3)
            ecrire_paragraphe(pdf, f"Marqueur trouvé : {self.capture.flag}")

    def ajout_attaques(self, pdf: FPDF) -> None:
        lst_attaques = list(self.capture.attacks)
        if not lst_attaques:
            ecrire_paragraphe(pdf, "Aucune attaque détectée : tout va bien.")
        else:
            self.ajout_tableau_attaques(pdf, lst_attaques)
        self.ajout_flag(pdf)

    def ajout_graph(self, pdf: FPDF) -> None:
        protos = list(self.capture.protocols.items())[:MAX_BARS]
        if self.graph == "" or not protos:
            return
        with pdf.unbreakable() as section:
            self.ajout_section(section, "Graphique : nombre de paquets par protocole")
            self.dessiner_barres(section, protos)

    @staticmethod
    def dessiner_une_barre(pdf: FPDF, proto: str, nb: int, largeur: float) -> None:
        pdf.cell(LABEL_WIDTH_MM, BAR_HEIGHT_MM, f"{txt_pdf(proto)}  ", align="R")
        # la barre est une cellule remplie : elle suit les sauts de page comme du texte
        pdf.cell(max(largeur, 0.5), BAR_HEIGHT_MM, "", fill=True)
        pdf.cell(VALUE_WIDTH_MM, BAR_HEIGHT_MM, f"  {nb}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(BAR_GAP_MM)

    @staticmethod
    def dessiner_barres(pdf: FPDF, protos: list[tuple[str, int]]) -> None:
        nb_max = max(nb for _, nb in protos)
        largeur_barres = pdf.epw - LABEL_WIDTH_MM - VALUE_WIDTH_MM
        pdf.set_font(FONT, size=10)
        pdf.set_fill_color(*BAR_COLOR)
        for proto, nb in protos:
            Report.dessiner_une_barre(pdf, proto, nb, largeur_barres * nb / nb_max)

    def save(self, filename: str) -> None:
        pdf = self.concat_report()
        pdf.output(filename)
        logger.info(f"Rapport enregistré dans {filename}")

    def constr_resultat_json(self) -> dict:
        return {
            "protocols": dict(self.capture.protocols),
            "attacks": [
                {"type": attaque.attack_type, "attacker": attaque.recup_attaquant()}
                for attaque in self.capture.attacks
            ],
            "flag": self.capture.flag,
        }

    def ecrire_rapport_json(self, filename: str) -> None:
        """Enregistre le report.json lu par le correcteur : protocoles, attaques et marqueur."""
        with Path(filename).open("w", encoding="utf-8") as fichier_json:
            json.dump(self.constr_resultat_json(), fichier_json, indent=2, ensure_ascii=False)
        logger.info(f"Résultat pour le correcteur enregistré dans {filename}")

    def generate(self, param: str) -> None:
        """Prépare le graphique (param="graph") ou le tableau (param="array")."""
        if param == "graph":
            self.graph = enreg_graph_svg(self.capture.protocols)
        elif param == "array":
            self.array = list(self.capture.protocols.items())
