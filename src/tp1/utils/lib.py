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


def parse_interface_choice(choice: str, interfaces: list[str]) -> str | None:
    """
    Convertit la saisie de l'utilisateur en nom d'interface

    :param choice: numéro ou nom de l'interface, vide pour garder l'interface par défaut de scapy
    :param interfaces: interfaces disponibles
    :return: nom de l'interface, None si la saisie ne correspond à aucune interface
    """
    choice = choice.strip()
    if choice == "":
        return str(conf.iface)
    if choice in interfaces:
        return choice
    if choice.isdigit() and int(choice) < len(interfaces):
        return interfaces[int(choice)]
    return None


def choose_interface() -> str:
    """
    Affiche les interfaces réseau et demande à l'utilisateur d'en choisir une,
    jusqu'à ce que le choix soit valide (une faute de frappe ne lance pas la capture ailleurs)

    :return: network interface
    """
    interfaces = get_if_list()
    for index, interface in enumerate(interfaces):
        logger.info(f"{index} : {interface}")

    while True:
        choice = input(f"Numéro de l'interface à écouter (Entrée = {conf.iface}) : ")
        interface = parse_interface_choice(choice, interfaces)
        if interface is not None:
            return interface
        logger.warning(f"Choix invalide : {choice!r}")


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
