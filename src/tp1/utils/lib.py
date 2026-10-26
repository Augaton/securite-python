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

# Raw data, plus the original packet headers copied into an ICMP error (still an ICMP packet)
PAYLOAD_LAYERS = (Raw, Padding, IPerror, IPerror6, TCPerror, UDPerror, ICMPerror)

# Scapy layer -> reported protocol name, in encapsulation order (link to application)
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
# Scapy does not decode HTTP by default, so we spot it from the cleartext payload
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
    logger.info(f"No input available, default interface: {conf.iface}")
    return str(conf.iface)


def choose_interface() -> str:
    interfaces = get_if_list()
    for index, interface in enumerate(interfaces):
        logger.info(f"{index}: {interface}")

    if sys.stdin is None or not sys.stdin.isatty():
        return use_default_interface()
    while True:
        try:
            choice = input(f"Interface number to listen on (Enter = {conf.iface}): ")
        except EOFError:
            return use_default_interface()
        interface = parse_interface_choice(choice, interfaces)
        if interface is not None:
            return interface
        logger.warning(f"Invalid choice: {choice!r}")


def get_protocol(packet: Packet) -> str:
    """Most specific protocol of a packet (Ether/IP/UDP/DNS -> "DNS"); "Other" for raw data only."""
    protocol_layers = [layer for layer in packet.layers() if layer not in PAYLOAD_LAYERS]
    if not protocol_layers:
        return "Other"
    return protocol_layers[-1].__name__


def is_http(packet: Packet) -> bool:
    return packet.haslayer(TCP) and packet.haslayer(Raw) and bytes(packet[Raw].load).startswith(HTTP_SIGNATURES)


def get_protocols(packet: Packet) -> list[str]:
    """Every protocol present in a packet, e.g. Ether/IP/TCP/HTTP -> [Ethernet, IP, TCP, HTTP]."""
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
    """Give back to the sudo user the log files root created at startup."""
    for handler in logging.getLogger().handlers:
        if isinstance(handler, logging.FileHandler):
            # Without follow_symlinks=False, a link app.log -> /etc/shadow would give its target to the user
            os.chown(handler.baseFilename, user.pw_uid, user.pw_gid, follow_symlinks=False)


def drop_privileges() -> None:
    """Permanently drop root to switch back to the user who ran sudo."""
    if os.geteuid() != 0:
        return
    user = get_sudo_user()
    if user is None:
        logger.warning("Running as root without sudo: no user to drop to, everything runs as root")
        return
    give_log_files_to(user)
    # Groups and gid first: once the uid has changed, we may no longer modify them
    os.initgroups(user.pw_name, user.pw_gid)
    os.setgid(user.pw_gid)
    os.setuid(user.pw_uid)
    if 0 in os.getresuid():
        message = "Could not drop root privileges"
        raise RuntimeError(message)
    os.environ["HOME"] = user.pw_dir
    logger.info(f"Root privileges dropped, continuing as {user.pw_name}")
