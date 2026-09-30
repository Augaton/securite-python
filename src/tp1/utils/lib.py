from scapy.all import Packet, conf, get_if_list

from src.tp1.utils.config import logger

# Protocoles qu'on reconnait. L'ordre compte : DNS doit être avant UDP sinon tous les paquets DNS
# seraient comptés comme UDP
KNOWN_PROTOCOLS = ["DNS", "TCP", "UDP", "ICMP", "ARP"]


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
    Retourne le protocole d'un paquet (le premier de KNOWN_PROTOCOLS qui est dans le paquet)

    :param packet: paquet capturé avec scapy
    :return: nom du protocole, "Autre" si on le connait pas
    """
    for protocol in KNOWN_PROTOCOLS:
        if packet.haslayer(protocol):
            return protocol
    return "Autre"
