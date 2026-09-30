from scapy.all import conf, get_if_list

from src.tp1.utils.config import logger


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
