from collections import Counter, defaultdict
from dataclasses import dataclass

from scapy.all import ARP, IP, TCP, Ether, IPv6, Packet

UNKNOWN = "inconnue"
# Nombre de ports différents visés par des SYN à partir duquel on considère que c'est un scan
SYN_SCAN_MIN_PORTS = 10


@dataclass(frozen=True)
class Attack:
    """
    Tentative d'attaque repérée dans le trafic capturé
    """

    attack_type: str  # identifiant de l'attaque (celui du report.json), ex : "arp_spoofing"
    name: str  # nom affiché, ex : "ARP spoofing"
    protocol: str  # protocole utilisé par l'attaquant
    attacker_ip: str  # adresse réseau
    attacker_mac: str  # adresse physique
    details: str

    def get_attacker(self) -> str:
        """
        Adresse qui identifie l'attaquant : sa MAC pour l'ARP (réseau local), son IP sinon
        """
        return self.attacker_mac if self.protocol == "ARP" else self.attacker_ip

    def describe(self) -> str:
        """
        Décrit l'attaque en une ligne (logs et résumé)
        """
        return (
            f"{self.name} ({self.protocol}) depuis {self.attacker_ip} / {self.attacker_mac} : {self.details}"
        )


def get_source_mac(packet: Packet) -> str:
    """
    Retourne l'adresse MAC source d'un paquet
    """
    return packet[Ether].src if packet.haslayer(Ether) else UNKNOWN


def get_source_ip(packet: Packet) -> str:
    """
    Retourne l'adresse IP source d'un paquet (IPv4 ou IPv6)
    """
    for ip_layer in (IP, IPv6):
        if packet.haslayer(ip_layer):
            return packet[ip_layer].src
    return UNKNOWN


def get_destination_ip(packet: Packet) -> str:
    """
    Retourne l'adresse IP destination d'un paquet (IPv4 ou IPv6)
    """
    for ip_layer in (IP, IPv6):
        if packet.haslayer(ip_layer):
            return packet[ip_layer].dst
    return UNKNOWN


def find_ip_of_mac(packets: list[Packet], mac: str) -> str:
    """
    Retourne l'IP qu'une MAC utilise dans son propre trafic IP : en ARP spoofing l'IP annoncée est
    celle de la victime, pas celle de l'attaquant
    """
    for packet in packets:
        if get_source_mac(packet) == mac and get_source_ip(packet) != UNKNOWN:
            return get_source_ip(packet)
    return UNKNOWN


def count_arp_announces(packets: list[Packet]) -> tuple[dict[str, Counter], dict[str, set[str]]]:
    """
    Chaque paquet ARP annonce "l'IP psrc est à la MAC hwsrc" (0.0.0.0 = machine sans IP, ignorée).

    :return: les MAC annoncées pour chaque IP (avec leur nombre d'annonces, dans l'ordre d'arrivée)
             et les IP annoncées par chaque MAC
    """
    macs_by_ip = defaultdict(Counter)
    ips_by_mac = defaultdict(set)
    for packet in packets:
        if packet.haslayer(ARP) and packet[ARP].psrc != "0.0.0.0":
            macs_by_ip[packet[ARP].psrc][packet[ARP].hwsrc] += 1
            ips_by_mac[packet[ARP].hwsrc].add(packet[ARP].psrc)
    return macs_by_ip, ips_by_mac


def find_arp_spoofers(packets: list[Packet]) -> dict[str, set[str]]:
    """
    Retourne les MAC qui usurpent des IP, avec les IP usurpées. Une MAC est suspecte si elle :
    - annonce plusieurs IP : elle se fait passer pour plusieurs machines (ex : passerelle + victime)
    - ou annonce une IP déjà annoncée par une autre MAC, en insistant plus qu'elle
    """
    macs_by_ip, ips_by_mac = count_arp_announces(packets)
    spoofed_ips_by_mac = defaultdict(set)
    for mac, ips in ips_by_mac.items():
        if len(ips) > 1:
            spoofed_ips_by_mac[mac] |= ips - {find_ip_of_mac(packets, mac)}
    for ip, mac_counts in macs_by_ip.items():
        if len(mac_counts) > 1:
            macs = list(mac_counts)
            # à égalité on accuse la dernière MAC arrivée : la première est sûrement la vraie
            spoofer = max(macs, key=lambda mac: (mac_counts[mac], macs.index(mac)))
            spoofed_ips_by_mac[spoofer].add(ip)
    return spoofed_ips_by_mac


def detect_arp_spoofing(packets: list[Packet]) -> list[Attack]:
    """
    ARP spoofing : l'attaquant envoie de fausses annonces ARP pour recevoir le trafic destiné à une
    autre machine (souvent la passerelle) et l'espionner ou le modifier (homme du milieu)
    """
    return [
        Attack(
            attack_type="arp_spoofing",
            name="ARP spoofing",
            protocol="ARP",
            attacker_ip=find_ip_of_mac(packets, mac),
            attacker_mac=mac,
            details=f"se fait passer pour {', '.join(sorted(spoofed_ips))}",
        )
        for mac, spoofed_ips in find_arp_spoofers(packets).items()
    ]


def detect_syn_scan(packets: list[Packet]) -> list[Attack]:
    """
    Scan SYN : l'attaquant envoie des demandes de connexion TCP (SYN seul, sans ACK) vers beaucoup
    de ports pour trouver les services ouverts, sans jamais terminer les connexions
    """
    ports_by_ip = defaultdict(set)  # IP source -> ports visés
    targets_by_ip = defaultdict(set)  # IP source -> machines visées
    mac_by_ip = {}
    for packet in packets:
        if packet.haslayer(TCP) and packet[TCP].flags == "S":
            source_ip = get_source_ip(packet)
            ports_by_ip[source_ip].add(packet[TCP].dport)
            targets_by_ip[source_ip].add(get_destination_ip(packet))
            mac_by_ip.setdefault(source_ip, get_source_mac(packet))
    return [
        Attack(
            attack_type="syn_scan",
            name="Scan SYN",
            protocol="TCP",
            attacker_ip=ip,
            attacker_mac=mac_by_ip[ip],
            details=f"{len(ports)} ports visés sur {', '.join(sorted(targets_by_ip[ip]))}",
        )
        for ip, ports in ports_by_ip.items()
        if len(ports) >= SYN_SCAN_MIN_PORTS
    ]


def detect_attacks(packets: list[Packet]) -> list[Attack]:
    """
    Cherche toutes les attaques connues dans les paquets capturés

    :param packets: paquets capturés
    :return: tentatives d'attaque trouvées, liste vide si tout va bien
    """
    return detect_arp_spoofing(packets) + detect_syn_scan(packets)
