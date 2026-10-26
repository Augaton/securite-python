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


def parse_interface_choice(choice: str, interfaces: list[str]) -> str | None:
    choice = choice.strip()
    if choice == "":
        return str(conf.iface)
    if choice in interfaces:
        return choice
    if choice.isdigit() and int(choice) < len(interfaces):
        return interfaces[int(choice)]
    return None


def use_default_interface() -> str:
    logger.info(f"Pas de saisie possible, interface par défaut : {conf.iface}")
    return str(conf.iface)


def choose_interface() -> str:
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
    """Protocole le plus précis d'un paquet (Ether / IP / UDP / DNS -> "DNS") ; "Autre" si données brutes."""
    protocol_layers = [layer for layer in packet.layers() if layer not in PAYLOAD_LAYERS]
    if not protocol_layers:
        return "Autre"
    return protocol_layers[-1].__name__


def is_http(packet: Packet) -> bool:
    return packet.haslayer(TCP) and packet.haslayer(Raw) and bytes(packet[Raw].load).startswith(HTTP_SIGNATURES)


def get_protocols(packet: Packet) -> list[str]:
    """Tous les protocoles présents dans un paquet, ex : Ether/IP/TCP/HTTP -> [Ethernet, IP, TCP, HTTP]."""
    protocols = [name for layer, name in PROTOCOL_LAYERS if packet.haslayer(layer)]
    if is_http(packet):
        protocols.append("HTTP")
    return protocols or [get_protocol(packet)]


def format_share(count: int, total: int) -> str:
    share = count / total * 100 if total else 0.0
    return f"{share:.1f} %"


def get_sudo_user() -> pwd.struct_passwd | None:
    sudo_uid = os.environ.get("SUDO_UID")
    if sudo_uid is None:
        return None
    return pwd.getpwuid(int(sudo_uid))


def give_log_files_to(user: pwd.struct_passwd) -> None:
    """Rend à l'utilisateur les fichiers de log créés par root au démarrage."""
    for handler in logging.getLogger().handlers:
        if isinstance(handler, logging.FileHandler):
            # sans follow_symlinks=False, un lien app.log -> /etc/shadow donnerait sa cible à l'utilisateur
            os.chown(handler.baseFilename, user.pw_uid, user.pw_gid, follow_symlinks=False)


def drop_privileges() -> None:
    """Abandonne définitivement les droits root pour repasser sous l'utilisateur qui a lancé sudo."""
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
