import json
from datetime import datetime

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
        date = datetime.now().strftime("%d/%m/%Y à %H:%M")
        subtitle = f"Généré le {date} - interface {self.capture.interface}"
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

    def add_attacks(self, pdf: FPDF) -> None:
        """
        Ajoute chaque tentative d'attaque avec le protocole et les adresses réseau/physique de
        l'attaquant, ou indique que tout va bien, puis le marqueur trouvé dans le trafic
        """
        attacks = list(self.capture.attacks)
        if not attacks:
            pdf.multi_cell(0, 6, "Aucune attaque détectée : tout va bien.", new_x="LMARGIN", new_y="NEXT")
        else:
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
        if self.capture.flag is not None:
            pdf.ln(3)
            pdf.multi_cell(
                0, 6, to_pdf_text(f"Marqueur trouvé : {self.capture.flag}"), new_x="LMARGIN", new_y="NEXT"
            )

    def add_graph(self, pdf: FPDF) -> None:
        """
        Ajoute le graphique, sur la page suivante avec son titre s'il ne tient pas en bas de page
        """
        if self.graph == "":
            return
        with pdf.unbreakable() as section:
            self.add_section(section, "Graphique")
            section.image(self.graph, w=pdf.epw)

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
        with open(filename, "w", encoding="utf-8") as json_file:
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
