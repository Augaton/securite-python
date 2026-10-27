import logging
import os
import pwd
import sys

from scapy.all import (
    ARP,
    DNS,
    ICMP,
    IP,
    TCP,
    UDP,
    Ether,
    ICMPerror,
    IPerror,
    IPerror6,
    IPv6,
    Packet,
    Padding,
    Raw,
    TCPerror,
    UDPerror,
    conf,
    get_if_list,
)

from src.tp1.utils.config import logger

# données brutes, et en-têtes du paquet d'origine recopiés dans une erreur ICMP (qui reste un paquet ICMP)
PAYLOAD_LAYERS = (Raw, Padding, IPerror, IPerror6, TCPerror, UDPerror, ICMPerror)

# couche scapy -> nom de protocole affiché, dans l'ordre d'encapsulation
PROTOCOL_LAYERS = (
    (Ether, "Ethernet"),
    (ARP, "ARP"),
    (IP, "IP"),
    (IPv6, "IPv6"),
    (ICMP, "ICMP"),
    (TCP, "TCP"),
    (UDP, "UDP"),
    (DNS, "DNS"),
)
# scapy ne décode pas HTTP par défaut, on le repère donc sur le début de la charge en clair
HTTP_SIGNATURES = (b"GET ", b"POST ", b"PUT ", b"PATCH ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"HTTP/")


def hello_world() -> str:
    return "hello world"


def lire_choix_interface(choix: str, lst_interfaces: list[str]) -> str | None:
    choix = choix.strip()
    if choix == "":
        return str(conf.iface)
    if choix in lst_interfaces:
        return choix
    if choix.isdigit() and int(choix) < len(lst_interfaces):
        return lst_interfaces[int(choix)]
    return None


def recup_interface_defaut() -> str:
    logger.info(f"Pas de saisie possible, interface par défaut : {conf.iface}")
    return str(conf.iface)


def afficher_lst_interfaces(lst_interfaces: list[str]) -> None:
    for index, interface in enumerate(lst_interfaces):
        logger.info(f"{index} : {interface}")


def verif_clavier_dispo() -> bool:
    return sys.stdin is not None and sys.stdin.isatty()


def demander_interface(lst_interfaces: list[str]) -> str:
    while True:
        try:
            choix = input(f"Numéro de l'interface à écouter (Entrée = {conf.iface}) : ")
        except EOFError:
            return recup_interface_defaut()
        interface = lire_choix_interface(choix, lst_interfaces)
        if interface is not None:
            return interface
        logger.warning(f"Choix invalide : {choix!r}")


def choose_interface() -> str:
    lst_interfaces = get_if_list()
    afficher_lst_interfaces(lst_interfaces)
    if not verif_clavier_dispo():
        return recup_interface_defaut()
    return demander_interface(lst_interfaces)


def recup_proto_principal(packet: Packet) -> str:
    """Protocole le plus précis d'un paquet (Ether / IP / UDP / DNS -> "DNS") ; "Autre" si données brutes."""
    couches_proto = [couche for couche in packet.layers() if couche not in PAYLOAD_LAYERS]
    if not couches_proto:
        return "Autre"
    return couches_proto[-1].__name__


def verif_http(packet: Packet) -> bool:
    return (
        packet.haslayer(TCP) and packet.haslayer(Raw) and bytes(packet[Raw].load).startswith(HTTP_SIGNATURES)
    )


def recup_lst_protos(packet: Packet) -> list[str]:
    """Tous les protocoles présents dans un paquet, ex : Ether/IP/TCP/HTTP -> [Ethernet, IP, TCP, HTTP]."""
    protos = [nom for couche, nom in PROTOCOL_LAYERS if packet.haslayer(couche)]
    if verif_http(packet):
        protos.append("HTTP")
    return protos or [recup_proto_principal(packet)]


def formater_part_pct(nb: int, total: int) -> str:
    part = nb / total * 100 if total else 0.0
    return f"{part:.1f} %"


def recup_user_sudo() -> pwd.struct_passwd | None:
    sudo_uid = os.environ.get("SUDO_UID")
    if sudo_uid is None:
        return None
    return pwd.getpwuid(int(sudo_uid))


def rendre_fichiers_log_a(user: pwd.struct_passwd) -> None:
    """Rend à l'utilisateur les fichiers de log créés par root au démarrage."""
    for handler in logging.getLogger().handlers:
        if isinstance(handler, logging.FileHandler):
            # sans follow_symlinks=False, un lien app.log -> /etc/shadow donnerait sa cible à l'utilisateur
            os.chown(handler.baseFilename, user.pw_uid, user.pw_gid, follow_symlinks=False)


def changer_uid_gid(user: pwd.struct_passwd) -> None:
    # groupes et gid d'abord : une fois l'uid changé, on n'a plus le droit de les modifier
    os.initgroups(user.pw_name, user.pw_gid)
    os.setgid(user.pw_gid)
    os.setuid(user.pw_uid)
    if 0 in os.getresuid():
        message = "Impossible d'abandonner les droits root"
        raise RuntimeError(message)


def abandonner_droits_root() -> None:
    """Abandonne définitivement les droits root pour repasser sous l'utilisateur qui a lancé sudo."""
    if os.geteuid() != 0:
        return
    user = recup_user_sudo()
    if user is None:
        logger.warning("Lancé en root sans sudo : pas d'utilisateur vers qui repasser, tout tourne en root")
        return
    rendre_fichiers_log_a(user)
    changer_uid_gid(user)
    os.environ["HOME"] = user.pw_dir
    logger.info(f"Droits root abandonnés, la suite tourne en tant que {user.pw_name}")
