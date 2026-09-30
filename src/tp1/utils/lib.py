import logging
import os
import pwd

from scapy.all import (
    ICMPerror,
    IPerror,
    IPerror6,
    Packet,
    Padding,
    Raw,
    TCPerror,
    UDPerror,
    conf,
    get_if_list,
)

from src.tp1.utils.config import logger

# Couches qui ne donnent pas le protocole du paquet : les données brutes, et l'en-tête du paquet
# d'origine recopié dans une erreur ICMP ("port injoignable" est un paquet ICMP, pas un paquet UDP)
PAYLOAD_LAYERS = (Raw, Padding, IPerror, IPerror6, TCPerror, UDPerror, ICMPerror)


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


def format_share(count: int, total: int) -> str:
    """
    Retourne la part d'un nombre de paquets dans le total, en pourcentage

    :param count: nombre de paquets
    :param total: nombre total de paquets
    :return: pourcentage, ex : "25.0 %"
    """
    share = count / total * 100 if total else 0.0
    return f"{share:.1f} %"


def get_sudo_user() -> pwd.struct_passwd | None:
    """
    Retourne l'utilisateur qui a lancé le programme avec sudo

    :return: son compte (nom, uid, gid, dossier personnel), None si le programme n'a pas été lancé avec sudo
    """
    sudo_uid = os.environ.get("SUDO_UID")
    if sudo_uid is None:
        return None
    return pwd.getpwuid(int(sudo_uid))


def give_log_files_to(user: pwd.struct_passwd) -> None:
    """
    Rend les fichiers de log à l'utilisateur : app.log est créé par root dès le démarrage (import de
    la config), sans ça on ne pourrait plus écrire dedans ni lancer les tests sans sudo
    """
    for handler in logging.getLogger().handlers:
        if isinstance(handler, logging.FileHandler):
            # follow_symlinks=False : si app.log est un lien, root ne donne pas sa cible (ex : /etc/shadow)
            os.chown(handler.baseFilename, user.pw_uid, user.pw_gid, follow_symlinks=False)


def drop_privileges() -> None:
    """
    Abandonne définitivement les droits root pour repasser sous l'utilisateur qui a lancé sudo.
    Seule l'ouverture du socket de capture a besoin de root : l'analyse des paquets reçus (qui peuvent
    venir d'un attaquant) et l'écriture des fichiers se font ensuite sans ces droits.
    """
    if os.geteuid() != 0:
        return
    user = get_sudo_user()
    if user is None:
        logger.warning("Lancé en root sans sudo : pas d'utilisateur vers qui repasser, tout tourne en root")
        return
    give_log_files_to(user)
    # les groupes et le gid d'abord : une fois l'uid changé, on n'a plus le droit de les modifier
    os.initgroups(user.pw_name, user.pw_gid)
    os.setgid(user.pw_gid)
    os.setuid(user.pw_uid)
    if 0 in os.getresuid():
        raise RuntimeError("Impossible d'abandonner les droits root")
    os.environ["HOME"] = user.pw_dir
    logger.info(f"Droits root abandonnés, la suite tourne en tant que {user.pw_name}")
