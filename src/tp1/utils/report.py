from fpdf import FPDF

from src.tp1.utils.capture import Capture
from src.tp1.utils.config import logger
from src.tp1.utils.graph import save_graph


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
        pdf.add_page()

        pdf.set_font("Helvetica", "B", 18)
        pdf.cell(0, 15, self.title, align="C", new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", size=12)
        pdf.multi_cell(0, 8, self.summary, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)

        self.add_array(pdf)
        pdf.ln(5)

        if self.graph != "":
            pdf.image(self.graph, w=170)
        return pdf

    def add_array(self, pdf: FPDF) -> None:
        """
        Ajoute le tableau protocole / nombre de paquets dans le PDF
        """
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(100, 10, "Protocole", border=1)
        pdf.cell(60, 10, "Nombre de paquets", border=1, new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", size=12)
        for protocol, count in self.array:
            pdf.cell(100, 10, protocol, border=1)
            pdf.cell(60, 10, str(count), border=1, new_x="LMARGIN", new_y="NEXT")

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
