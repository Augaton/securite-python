from pathlib import Path

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


def create_graph(protocols: dict) -> pygal.HorizontalBar:
    """
    Crée un histogramme horizontal du nombre de paquets par protocole

    :param protocols: {protocole: nombre de paquets}
    :return: graphique pygal
    """
    graph = pygal.HorizontalBar(
        style=GRAPH_STYLE,
        title="Nombre de paquets par protocole",
        show_legend=False,
        height=BASE_HEIGHT_PX + BAR_HEIGHT_PX * max(len(protocols), 1),
        no_data_text="Aucun paquet capturé",
        order_min=0,  # graduations entières : on compte des paquets
        js=[],  # pas de script chargé depuis internet
    )
    # pygal dessine la première barre en bas : ordre croissant pour avoir la plus grande en haut
    ordered_protocols = sorted(protocols.items(), key=lambda item: item[1])
    graph.x_labels = [protocol for protocol, _ in ordered_protocols]
    graph.add("Paquets", [count for _, count in ordered_protocols])
    return graph


def save_graph(protocols: dict, directory: Path = Path()) -> str:
    """
    Enregistre le graphique pygal en SVG, à ouvrir dans le navigateur (l'interface graphique)

    :param protocols: {protocole: nombre de paquets}
    :param directory: dossier où écrire le graphique
    :return: chemin du fichier SVG
    """
    svg_path = str(directory / GRAPH_SVG)
    create_graph(protocols).render_to_file(svg_path)
    logger.info(f"Graphique enregistré dans {svg_path}")
    return svg_path
