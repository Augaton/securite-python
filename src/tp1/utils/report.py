import json
from datetime import datetime, timezone
from pathlib import Path

from fpdf import FPDF
from fpdf.fonts import FontFace

from src.tp1.utils.capture import Capture
from src.tp1.utils.config import logger
from src.tp1.utils.graph import save_graph
from src.tp1.utils.lib import format_share

FONT = "Helvetica"
MARGIN_MM = 20
GREY_TEXT = (82, 81, 78)
HEADINGS_STYLE = FontFace(emphasis="BOLD", fill_color=(240, 239, 236))
# Histogramme du PDF : une ligne par protocole (nom, barre, nombre de paquets)
BAR_COLOR = (42, 120, 214)  # le même bleu que le graphique pygal
LABEL_WIDTH_MM = 45
VALUE_WIDTH_MM = 22
BAR_HEIGHT_MM = 5
BAR_GAP_MM = 1.5
MAX_BARS = 25  # au-delà le graphique ne tient plus sur une page (le tableau garde tout)


def to_pdf_text(text: str) -> str:
    """
    Les polices de base de fpdf ne gèrent que le latin-1 : les autres caractères (par exemple ceux
    envoyés par l'attaquant dans une requête) sont remplacés par "?" au lieu de faire planter le PDF
    """
    return str(text).encode("latin-1", "replace").decode("latin-1")


class Report:
    def __init__(self, capture: Capture, filename: str, summary: str):
        self.capture = capture
        self.filename = filename
        self.title = "Rapport de capture réseau"
        self.summary = summary
        self.array = []  # lignes du tableau : (protocole, nombre de paquets)
        self.graph = ""  # chemin de l'image du graphique

    def concat_report(self) -> FPDF:
        """
        Concat all data in report (titre, résumé, tableau, légitimité du trafic et graphique)
        """
        pdf = FPDF()
        pdf.set_margins(MARGIN_MM, MARGIN_MM)
        pdf.set_auto_page_break(True, margin=MARGIN_MM)
        pdf.add_page()
        self.add_title(pdf)

        self.add_section(pdf, "Résumé")
        pdf.multi_cell(0, 6, to_pdf_text(self.summary), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(6)

        self.add_section(pdf, "Répartition des paquets par protocole")
        self.add_array(pdf)
        pdf.ln(6)

        self.add_section(pdf, "Légitimité du trafic")
        self.add_attacks(pdf)
        pdf.ln(6)

        self.add_graph(pdf)
        return pdf

    def add_title(self, pdf: FPDF) -> None:
        """
        Ajoute le titre du rapport avec la date et l'interface écoutée
        """
        pdf.set_font(FONT, "B", 18)
        pdf.cell(0, 10, self.title, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font(FONT, size=10)
        pdf.set_text_color(*GREY_TEXT)
        date = datetime.now(timezone.utc).astimezone().strftime("%d/%m/%Y à %H:%M")
        subtitle = f"Généré le {date} - {self.capture.get_source()}"
        pdf.cell(0, 6, to_pdf_text(subtitle), new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0)
        pdf.ln(6)

    @staticmethod
    def add_section(pdf: FPDF, title: str) -> None:
        """
        Ajoute le titre d'une partie du rapport puis repasse en police normale
        """
        pdf.set_font(FONT, "B", 13)
        pdf.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font(FONT, size=11)

    def add_array(self, pdf: FPDF) -> None:
        """
        Ajoute le tableau protocole / nombre de paquets / part du trafic / légitimité, avec le total
        """
        total = sum(count for _, count in self.array)
        with pdf.table(
            col_widths=(3, 1.6, 1.8, 3.6),
            text_align=("LEFT", "RIGHT", "RIGHT", "LEFT"),
            borders_layout="HORIZONTAL_LINES",
            headings_style=HEADINGS_STYLE,
            line_height=7,
        ) as table:
            table.row(("Protocole", "Paquets", "Part du trafic", "Trafic"))
            for protocol, count in self.array:
                table.row((protocol, str(count), format_share(count, total), self.get_legitimacy(protocol)))
            table.row(("Total", str(total), format_share(total, total), ""))

    def get_legitimacy(self, protocol: str) -> str:
        """
        Indique si le trafic d'un protocole est légitime, sinon les attaques qui passent par lui
        """
        attack_names = [attack.name for attack in self.capture.attacks if attack.protocol == protocol]
        if not attack_names:
            return "Légitime"
        return "Illégitime : " + ", ".join(attack_names)

    @staticmethod
    def add_attacks_table(pdf: FPDF, attacks: list) -> None:
        """
        Ajoute le tableau des attaques : une ligne par attaque avec l'IP et la MAC de l'attaquant
        """
        with pdf.table(
            col_widths=(2.2, 1.8, 2.4, 3, 4.6),
            text_align="LEFT",
            borders_layout="HORIZONTAL_LINES",
            headings_style=HEADINGS_STYLE,
            line_height=6,
        ) as table:
            table.row(("Attaque", "Protocole", "IP attaquant", "MAC attaquant", "Détails"))
            for attack in attacks:
                cells = (
                    attack.name,
                    attack.protocol,
                    attack.attacker_ip,
                    attack.attacker_mac,
                    attack.details,
                )
                table.row(tuple(to_pdf_text(cell) for cell in cells))

    def add_attacks(self, pdf: FPDF) -> None:
        """
        Ajoute chaque tentative d'attaque avec le protocole et les adresses réseau/physique de
        l'attaquant, ou indique que tout va bien, puis le marqueur trouvé dans le trafic
        """
        attacks = list(self.capture.attacks)
        if not attacks:
            pdf.multi_cell(0, 6, "Aucune attaque détectée : tout va bien.", new_x="LMARGIN", new_y="NEXT")
        else:
            self.add_attacks_table(pdf, attacks)
        if self.capture.flag is not None:
            pdf.ln(3)
            pdf.multi_cell(
                0, 6, to_pdf_text(f"Marqueur trouvé : {self.capture.flag}"), new_x="LMARGIN", new_y="NEXT"
            )

    def add_graph(self, pdf: FPDF) -> None:
        """
        Ajoute l'histogramme du nombre de paquets par protocole, dessiné directement avec fpdf : passer
        le SVG de pygal en image demandait la bibliothèque système cairo, absente du bac à sable de
        correction (le programme plantait dès le démarrage). Il passe à la page suivante avec son
        titre s'il ne tient pas en bas de page
        """
        protocols = list(self.capture.protocols.items())[:MAX_BARS]
        if self.graph == "" or not protocols:
            return
        with pdf.unbreakable() as section:
            self.add_section(section, "Graphique : nombre de paquets par protocole")
            self.draw_bars(section, protocols)

    @staticmethod
    def draw_bars(pdf: FPDF, protocols: list[tuple[str, int]]) -> None:
        """
        Une barre horizontale par protocole, proportionnelle à son nombre de paquets. Les barres sont
        des cellules remplies de couleur : elles se placent et suivent les sauts de page comme du texte
        """
        max_count = max(count for _, count in protocols)
        bars_width = pdf.epw - LABEL_WIDTH_MM - VALUE_WIDTH_MM
        pdf.set_font(FONT, size=10)
        pdf.set_fill_color(*BAR_COLOR)
        for protocol, count in protocols:
            pdf.cell(LABEL_WIDTH_MM, BAR_HEIGHT_MM, f"{to_pdf_text(protocol)}  ", align="R")
            pdf.cell(max(bars_width * count / max_count, 0.5), BAR_HEIGHT_MM, "", fill=True)
            pdf.cell(VALUE_WIDTH_MM, BAR_HEIGHT_MM, f"  {count}", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(BAR_GAP_MM)

    def save(self, filename: str) -> None:
        """
        Save report in a file
        :param filename: nom du fichier PDF
        :return:
        """
        pdf = self.concat_report()
        pdf.output(filename)
        logger.info(f"Rapport enregistré dans {filename}")

    def save_json(self, filename: str) -> None:
        """
        Enregistre le résultat au format attendu par le correcteur (le PDF reste le livrable "humain") :
        {"protocols": {"TCP": 128}, "attacks": [{"type": "arp_spoofing", "attacker": "aa:bb:..."}],
         "flag": "ESGI{...}"}

        :param filename: nom du fichier JSON
        """
        result = {
            "protocols": dict(self.capture.protocols),
            "attacks": [
                {"type": attack.attack_type, "attacker": attack.get_attacker()}
                for attack in self.capture.attacks
            ],
            "flag": self.capture.flag,
        }
        with Path(filename).open("w", encoding="utf-8") as json_file:
            json.dump(result, json_file, indent=2, ensure_ascii=False)
        logger.info(f"Résultat pour le correcteur enregistré dans {filename}")

    def generate(self, param: str) -> None:
        """
        Generate graph and array
        """
        if param == "graph":
            self.graph = save_graph(self.capture.protocols)
        elif param == "array":
            self.array = list(self.capture.protocols.items())
