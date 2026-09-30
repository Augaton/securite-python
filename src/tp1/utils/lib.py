from scapy.all import Packet, Padding, Raw, conf, get_if_list

from src.tp1.utils.config import logger

# Couches qui transportent des données sans identifier de protocole
PAYLOAD_LAYERS = (Raw, Padding)


def hello_world() -> str:
    """
    Hello world function

    :return: "hello world"
    """
    return "hello world"


def choose_interface() -> str:
    """
    Affiche les interfaces réseau et demande à l'utilisateur d'en choisir une

    :return: network interface
    """
    interfaces = get_if_list()
    for index, interface in enumerate(interfaces):
        logger.info(f"{index} : {interface}")

    choice = input("Numéro de l'interface à écouter : ")
    if choice.isdigit() and int(choice) < len(interfaces):
        return interfaces[int(choice)]

    # si le choix est pas bon on prend l'interface par défaut de scapy
    logger.warning(f"Choix invalide, on prend l'interface par défaut : {conf.iface}")
    return str(conf.iface)


def get_protocol(packet: Packet) -> str:
    """
    Retourne le protocole le plus précis d'un paquet, c'est-à-dire sa dernière couche sans compter
    les données brutes. Ex : Ether / IP / UDP / DNS -> "DNS", Ether / IP / TCP / Raw -> "TCP"

    :param packet: paquet capturé avec scapy
    :return: nom du protocole, "Autre" si le paquet ne contient que des données brutes
    """
    protocol_layers = [layer for layer in packet.layers() if layer not in PAYLOAD_LAYERS]
    if not protocol_layers:
        return "Autre"
    return protocol_layers[-1].__name__
