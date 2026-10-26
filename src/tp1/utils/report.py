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
BAR_COLOR = (42, 120, 214)
LABEL_WIDTH_MM = 45
VALUE_WIDTH_MM = 22
BAR_HEIGHT_MM = 5
BAR_GAP_MM = 1.5
MAX_BARS = 25  # beyond this the chart no longer fits on a page (the table keeps everything)


def to_pdf_text(text: str) -> str:
    """Replace characters fpdf's core latin-1 fonts cannot render with "?"."""
    return str(text).encode("latin-1", "replace").decode("latin-1")


class Report:
    def __init__(self, capture: Capture, filename: str, summary: str):
        self.capture = capture
        self.filename = filename
        self.title = "Network capture report"
        self.summary = summary
        self.array = []
        self.graph = ""

    def concat_report(self) -> FPDF:
        pdf = FPDF()
        pdf.set_margins(MARGIN_MM, MARGIN_MM)
        pdf.set_auto_page_break(True, margin=MARGIN_MM)
        pdf.add_page()
        self.add_title(pdf)

        self.add_section(pdf, "Summary")
        pdf.multi_cell(0, 6, to_pdf_text(self.summary), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(6)

        self.add_section(pdf, "Packet distribution by protocol")
        self.add_array(pdf)
        pdf.ln(6)

        self.add_section(pdf, "Traffic legitimacy")
        self.add_attacks(pdf)
        pdf.ln(6)

        self.add_graph(pdf)
        return pdf

    def add_title(self, pdf: FPDF) -> None:
        pdf.set_font(FONT, "B", 18)
        pdf.cell(0, 10, self.title, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font(FONT, size=10)
        pdf.set_text_color(*GREY_TEXT)
        date = datetime.now(timezone.utc).astimezone().strftime("%d/%m/%Y at %H:%M")
        subtitle = f"Generated on {date} - {self.capture.get_source()}"
        pdf.cell(0, 6, to_pdf_text(subtitle), new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0)
        pdf.ln(6)

    @staticmethod
    def add_section(pdf: FPDF, title: str) -> None:
        pdf.set_font(FONT, "B", 13)
        pdf.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font(FONT, size=11)

    def add_array(self, pdf: FPDF) -> None:
        total = sum(count for _, count in self.array)
        with pdf.table(
            col_widths=(3, 1.6, 1.8, 3.6),
            text_align=("LEFT", "RIGHT", "RIGHT", "LEFT"),
            borders_layout="HORIZONTAL_LINES",
            headings_style=HEADINGS_STYLE,
            line_height=7,
        ) as table:
            table.row(("Protocol", "Packets", "Traffic share", "Legitimacy"))
            for protocol, count in self.array:
                table.row((protocol, str(count), format_share(count, total), self.get_legitimacy(protocol)))
            table.row(("Total", str(total), format_share(total, total), ""))

    def get_legitimacy(self, protocol: str) -> str:
        attack_names = [attack.name for attack in self.capture.attacks if attack.protocol == protocol]
        if not attack_names:
            return "Legitimate"
        return "Illegitimate: " + ", ".join(attack_names)

    @staticmethod
    def add_attacks_table(pdf: FPDF, attacks: list) -> None:
        with pdf.table(
            col_widths=(2.2, 1.8, 2.4, 3, 4.6),
            text_align="LEFT",
            borders_layout="HORIZONTAL_LINES",
            headings_style=HEADINGS_STYLE,
            line_height=6,
        ) as table:
            table.row(("Attack", "Protocol", "Attacker IP", "Attacker MAC", "Details"))
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
        attacks = list(self.capture.attacks)
        if not attacks:
            pdf.multi_cell(0, 6, "No attack detected: all good.", new_x="LMARGIN", new_y="NEXT")
        else:
            self.add_attacks_table(pdf, attacks)
        if self.capture.flag is not None:
            pdf.ln(3)
            pdf.multi_cell(
                0, 6, to_pdf_text(f"Marker found: {self.capture.flag}"), new_x="LMARGIN", new_y="NEXT"
            )

    def add_graph(self, pdf: FPDF) -> None:
        protocols = list(self.capture.protocols.items())[:MAX_BARS]
        if self.graph == "" or not protocols:
            return
        with pdf.unbreakable() as section:
            self.add_section(section, "Graph: packets per protocol")
            self.draw_bars(section, protocols)

    @staticmethod
    def draw_bars(pdf: FPDF, protocols: list[tuple[str, int]]) -> None:
        max_count = max(count for _, count in protocols)
        bars_width = pdf.epw - LABEL_WIDTH_MM - VALUE_WIDTH_MM
        pdf.set_font(FONT, size=10)
        pdf.set_fill_color(*BAR_COLOR)
        for protocol, count in protocols:
            pdf.cell(LABEL_WIDTH_MM, BAR_HEIGHT_MM, f"{to_pdf_text(protocol)}  ", align="R")
            # The bar is a filled cell: it follows page breaks like text
            pdf.cell(max(bars_width * count / max_count, 0.5), BAR_HEIGHT_MM, "", fill=True)
            pdf.cell(VALUE_WIDTH_MM, BAR_HEIGHT_MM, f"  {count}", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(BAR_GAP_MM)

    def save(self, filename: str) -> None:
        pdf = self.concat_report()
        pdf.output(filename)
        logger.info(f"Report saved to {filename}")

    def save_json(self, filename: str) -> None:
        """Write the report.json read by the grader: protocols, attacks and marker."""
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
        logger.info(f"Grader result saved to {filename}")

    def generate(self, param: str) -> None:
        """Prepare the chart (param="graph") or the table (param="array")."""
        if param == "graph":
            self.graph = save_graph(self.capture.protocols)
        elif param == "array":
            self.array = list(self.capture.protocols.items())
