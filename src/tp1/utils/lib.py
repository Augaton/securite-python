import logging
import os
import pwd
import sys

from scapy.all import ARP, ICMP, TCP, UDP, Packet, conf, get_if_list

from src.tp1.utils.config import logger

# comptés par protocole de transport comme l'exemple de la consigne ({"TCP": 128, "ARP": 12}) :
# un paquet DNS compte en UDP, une requête HTTP en TCP
TRANSPORT_PROTOCOLS = (ARP, TCP, UDP, ICMP)


def hello_world() -> str:
    """
    Hello world function

    :return: "hello world"
    """
    return "hello world"


def parse_interface_choice(choice: str, interfaces: list[str]) -> str | None:
    """
    Convertit la saisie de l'utilisateur en nom d'interface

    :param choice: numéro ou nom de l'interface, vide pour l'interface par défaut
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


def use_default_interface() -> str:
    """
    Retourne l'interface par défaut de scapy
    """
    logger.info(f"Pas de saisie possible, interface par défaut : {conf.iface}")
    return str(conf.iface)


def choose_interface() -> str:
    """
    Affiche les interfaces réseau et demande laquelle écouter, jusqu'à avoir un choix valide

    :return: network interface
    """
    interfaces = get_if_list()
    for index, interface in enumerate(interfaces):
        logger.info(f"{index} : {interface}")

    if sys.stdin is None or not sys.stdin.isatty():
        return use_default_interface()
    while True:
        try:
            choice = input(f"Numéro de l'interface à écouter (Entrée = {conf.iface}) : ")
        except EOFError:
            return use_default_interface()
        interface = parse_interface_choice(choice, interfaces)
        if interface is not None:
            return interface
        logger.warning(f"Choix invalide : {choice!r}")


def get_protocol(packet: Packet) -> str:
    """
    Retourne le protocole de transport d'un paquet (Ether / IP / UDP / DNS -> "UDP")

    :param packet: paquet capturé avec scapy
    :return: nom du protocole, "ICMPv6" ou "Autre" pour les paquets sans ARP, TCP, UDP ni ICMP
    """
    for protocol in TRANSPORT_PROTOCOLS:
        if packet.haslayer(protocol):
            return protocol.__name__
    if any(layer.__name__.startswith("ICMPv6") for layer in packet.layers()):
        return "ICMPv6"
    return "Autre"


def format_share(count: int, total: int) -> str:
    """
    Retourne la part d'un nombre de paquets dans le total

    :param count: nombre de paquets
    :param total: nombre total de paquets
    :return: pourcentage, ex : "25.0 %"
    """
    share = count / total * 100 if total else 0.0
    return f"{share:.1f} %"


def get_sudo_user() -> pwd.struct_passwd | None:
    """
    Retourne le compte de l'utilisateur qui a lancé sudo, None sans sudo
    """
    sudo_uid = os.environ.get("SUDO_UID")
    if sudo_uid is None:
        return None
    return pwd.getpwuid(int(sudo_uid))


def give_log_files_to(user: pwd.struct_passwd) -> None:
    """
    Rend à l'utilisateur les fichiers de log créés par root au démarrage
    """
    for handler in logging.getLogger().handlers:
        if isinstance(handler, logging.FileHandler):
            # sans follow_symlinks=False, un lien app.log -> /etc/shadow donnerait sa cible à l'utilisateur
            os.chown(handler.baseFilename, user.pw_uid, user.pw_gid, follow_symlinks=False)


def drop_privileges() -> None:
    """
    Abandonne définitivement les droits root pour repasser sous l'utilisateur qui a lancé sudo
    """
    if os.geteuid() != 0:
        return
    user = get_sudo_user()
    if user is None:
        logger.warning("Lancé en root sans sudo : pas d'utilisateur vers qui repasser, tout tourne en root")
        return
    give_log_files_to(user)
    # groupes et gid d'abord : une fois l'uid changé, on n'a plus le droit de les modifier
    os.initgroups(user.pw_name, user.pw_gid)
    os.setgid(user.pw_gid)
    os.setuid(user.pw_uid)
    if 0 in os.getresuid():
        message = "Impossible d'abandonner les droits root"
        raise RuntimeError(message)
    os.environ["HOME"] = user.pw_dir
    logger.info(f"Droits root abandonnés, la suite tourne en tant que {user.pw_name}")
