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
        Concat all data in report (titre, résumé, tableau et graphique)
        """
        pdf = FPDF()
        pdf.set_margins(MARGIN_MM, MARGIN_MM)
        pdf.set_auto_page_break(True, margin=MARGIN_MM)
        pdf.add_page()
        self.add_title(pdf)

        self.add_section(pdf, "Résumé")
        pdf.multi_cell(0, 6, self.summary, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(6)

        self.add_section(pdf, "Répartition des paquets par protocole")
        self.add_array(pdf)
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
        pdf.cell(
            0, 6, f"Généré le {date} - interface {self.capture.interface}", new_x="LMARGIN", new_y="NEXT"
        )
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
        Ajoute le tableau protocole / nombre de paquets / part du trafic, avec le total à la fin
        """
        total = sum(count for _, count in self.array)
        with pdf.table(
            col_widths=(3, 2, 2),
            text_align=("LEFT", "RIGHT", "RIGHT"),
            borders_layout="HORIZONTAL_LINES",
            headings_style=HEADINGS_STYLE,
            line_height=7,
        ) as table:
            table.row(("Protocole", "Nombre de paquets", "Part du trafic"))
            for protocol, count in self.array:
                table.row((protocol, str(count), format_share(count, total)))
            table.row(("Total", str(total), format_share(total, total)))

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

    def generate(self, param: str) -> None:
        """
        Generate graph and array
        """
        if param == "graph":
            self.graph = save_graph(self.capture.protocols)
        elif param == "array":
            self.array = list(self.capture.protocols.items())
