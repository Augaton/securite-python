import pygal
from pygal.style import Style

from src.tp1.utils.config import logger

GRAPH_SVG = "graph.svg"

# grille en trait plein : pygal la dessine en pointillés par défaut
GRAPH_STYLE = Style(
    background="#ffffff",
    plot_background="#ffffff",
    foreground="#52514e",
    foreground_strong="#0b0b0b",
    foreground_subtle="#e1e0d9",
    guide_stroke_color="#e1e0d9",
    guide_stroke_dasharray="none",
    major_guide_stroke_color="#c3c2b7",
    major_guide_stroke_dasharray="none",
    colors=("#2a78d6",),
    opacity=1,
    opacity_hover=0.8,
    font_family="'DejaVu Sans', 'Liberation Sans', Helvetica, Arial, sans-serif",
    label_font_size=14,
    major_label_font_size=14,
    title_font_size=18,
    no_data_font_size=24,
)
BASE_HEIGHT_PX = 140
BAR_HEIGHT_PX = 34


def trier_protos_croissant(protocols: dict) -> list[tuple[str, int]]:
    # pygal dessine la première barre en bas : ordre croissant pour avoir la plus grande en haut
    return sorted(protocols.items(), key=lambda item: item[1])


def calc_hauteur_graph(nb_protos: int) -> int:
    return BASE_HEIGHT_PX + BAR_HEIGHT_PX * max(nb_protos, 1)


def creer_graph_protos(protocols: dict) -> pygal.HorizontalBar:
    graph = pygal.HorizontalBar(
        style=GRAPH_STYLE,
        title="Nombre de paquets par protocole",
        show_legend=False,
        height=calc_hauteur_graph(len(protocols)),
        no_data_text="Aucun paquet capturé",
        order_min=0,  # graduations entières : on compte des paquets
        js=[],  # pas de script chargé depuis internet
    )
    protos_tries = trier_protos_croissant(protocols)
    graph.x_labels = [proto for proto, _ in protos_tries]
    graph.add("Paquets", [nb for _, nb in protos_tries])
    return graph


def enreg_graph_svg(protocols: dict) -> str:
    creer_graph_protos(protocols).render_to_file(GRAPH_SVG)
    logger.info(f"Graphique enregistré dans {GRAPH_SVG}")
    return GRAPH_SVG
