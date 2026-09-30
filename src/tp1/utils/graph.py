import pygal

from src.tp1.utils.config import logger

GRAPH_SVG = "graph.svg"
GRAPH_PNG = "graph.png"


def create_graph(protocols: dict) -> pygal.Bar:
    """
    Crée un histogramme avec le nombre de paquets de chaque protocole

    :param protocols: {protocole: nombre de paquets}
    :return: graphique pygal
    """
    graph = pygal.Bar(title="Nombre de paquets par protocole")
    for protocol, count in protocols.items():
        graph.add(protocol, count)
    return graph


def save_graph(protocols: dict) -> str:
    """
    Enregistre le graphique en SVG (à ouvrir dans le navigateur) et en PNG (pour le PDF,
    fpdf n'affiche pas bien le SVG de pygal)

    :param protocols: {protocole: nombre de paquets}
    :return: chemin de l'image PNG
    """
    graph = create_graph(protocols)
    graph.render_to_file(GRAPH_SVG)
    graph.render_to_png(GRAPH_PNG)
    logger.info(f"Graphique enregistré dans {GRAPH_SVG}")
    return GRAPH_PNG
