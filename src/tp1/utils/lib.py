import logging
import os
import pwd
import sys

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

# Raw data, plus the original packet headers copied into an ICMP error (still an ICMP packet)
PAYLOAD_LAYERS = (Raw, Padding, IPerror, IPerror6, TCPerror, UDPerror, ICMPerror)


def hello_world() -> str:
    return "hello world"


def parse_interface_choice(choice: str, interfaces: list[str]) -> str | None:
    """
    Turn the user's input into an interface name

    :param choice: interface number or name, empty for the default interface
    :param interfaces: available interfaces
    :return: interface name, None if the input matches no interface
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
    Return scapy's default interface
    """
    logger.info(f"No input available, default interface: {conf.iface}")
    return str(conf.iface)


def choose_interface() -> str:
    """
    List the network interfaces and ask which one to listen on, until a valid choice is given

    :return: network interface
    """
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
    """
    Return a packet's most specific protocol (Ether / IP / UDP / DNS -> "DNS")

    :param packet: packet captured with scapy
    :return: protocol name, "Other" if the packet only holds raw data
    """
    protocol_layers = [layer for layer in packet.layers() if layer not in PAYLOAD_LAYERS]
    if not protocol_layers:
        return "Other"
    return protocol_layers[-1].__name__


def format_share(count: int, total: int) -> str:
    """
    Return a packet count's share of the total

    :param count: packet count
    :param total: total packet count
    :return: percentage, e.g. "25.0 %"
    """
    share = count / total * 100 if total else 0.0
    return f"{share:.1f} %"


def get_sudo_user() -> pwd.struct_passwd | None:
    """
    Return the account of the user who ran sudo, None without sudo
    """
    sudo_uid = os.environ.get("SUDO_UID")
    if sudo_uid is None:
        return None
    return pwd.getpwuid(int(sudo_uid))


def give_log_files_to(user: pwd.struct_passwd) -> None:
    """
    Hand back to the user the log files root created at startup
    """
    for handler in logging.getLogger().handlers:
        if isinstance(handler, logging.FileHandler):
            # Without follow_symlinks=False, a link app.log -> /etc/shadow would give its target to the user
            os.chown(handler.baseFilename, user.pw_uid, user.pw_gid, follow_symlinks=False)


def drop_privileges() -> None:
    """
    Permanently give up root privileges to switch back to the user who ran sudo
    """
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
