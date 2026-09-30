import re
from collections import defaultdict
from dataclasses import dataclass
from urllib.parse import unquote, unquote_plus

from scapy.all import ARP, IP, TCP, Ether, IPv6, Packet, Raw

from src.tp1.utils.lib import get_protocol

UNKNOWN = "inconnue"
# Nombre de ports différents visés par des SYN à partir duquel on considère que c'est un scan
SYN_SCAN_MIN_PORTS = 10
HTTP_METHODS = ("GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HEAD ", "OPTIONS ")
# Morceaux de SQL typiques d'une injection
SQL_INJECTION_PATTERN = re.compile(
    r"""["']\s*(or|and)\s*["']?\w*["']?\s*="""  # ' OR '1'='1, ' AND 1=1, ' or ''='
    r"|\b(or|and)\s+\d+\s*=\s*\d+"  # OR 1=1 sans guillemet (champ numérique)
    r"|\bunion\s+(all\s+)?select\b"  # UNION SELECT : lire une autre table
    r"|;\s*(drop|delete|insert|update|select)\b"  # ; DROP TABLE : requête ajoutée à la suite
    r"""|["']\s*(--|#)(\s|&|$)|["']\s*/\*"""  # ' -- : la fin de la vraie requête est commentée
    r"|\b(sleep|pg_sleep|benchmark)\s*\("  # injection à l'aveugle, basée sur le temps de réponse
    r"|\binformation_schema\b",  # lecture de la structure de la base
    re.IGNORECASE,
)
# Marqueur unique glissé par le conteneur attaquant dans son injection SQL
FLAG_PATTERN = re.compile(r"ESGI\{[^}\s]*\}")


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


def is_ipv4_arp(arp: ARP) -> bool:
    """
    Vérifie que c'est un ARP classique (IPv4 sur Ethernet). Dans un ARP malformé, scapy donne les
    adresses en octets bruts au lieu de texte, ce qui faisait planter l'analyse : un seul paquet
    bizarre envoyé par un attaquant suffisait à couper l'outil
    """
    # hwlen et plen valent None dans un paquet construit à la main (calculés à l'envoi)
    return arp.hwtype == 1 and arp.ptype == 0x0800 and arp.hwlen in (None, 6) and arp.plen in (None, 4)


def count_arp_announces(packets: list[Packet]) -> tuple[dict[str, dict[str, int]], dict[str, set[str]]]:
    """
    Chaque paquet ARP annonce "l'IP psrc est à la MAC hwsrc" (0.0.0.0 = machine sans IP, ignorée).

    :return: les MAC annoncées pour chaque IP avec leur rang d'arrivée (0 = première vue),
             et les IP annoncées par chaque MAC
    """
    macs_by_ip = defaultdict(dict)
    ips_by_mac = defaultdict(set)
    for packet in packets:
        if packet.haslayer(ARP) and is_ipv4_arp(packet[ARP]) and packet[ARP].psrc != "0.0.0.0":
            ip, mac = packet[ARP].psrc, packet[ARP].hwsrc
            macs_by_ip[ip].setdefault(mac, len(macs_by_ip[ip]))
            ips_by_mac[mac].add(ip)
    return macs_by_ip, ips_by_mac


def find_arp_spoofers(packets: list[Packet], other_attacker_macs: set[str]) -> dict[str, set[str]]:
    """
    Retourne les MAC qui usurpent des IP, avec les IP usurpées. Une MAC usurpe :
    - toutes les IP qu'elle annonce si elle en annonce plusieurs (ex : passerelle + victime)
    - une IP déjà annoncée par une autre MAC. On accuse la MAC déjà suspecte (plusieurs IP annoncées,
      ou source d'une autre attaque), sinon la dernière arrivée : comme arpwatch, la première MAC vue
      pour une IP est la vraie. Le nombre d'annonces ne compte pas : la vraie passerelle peut en faire
      beaucoup plus que l'attaquant
    """
    macs_by_ip, ips_by_mac = count_arp_announces(packets)
    several_ips_macs = {mac for mac, ips in ips_by_mac.items() if len(ips) > 1}
    suspect_macs = several_ips_macs | other_attacker_macs
    spoofed_ips_by_mac = defaultdict(set)
    for mac in several_ips_macs:
        spoofed_ips_by_mac[mac] |= ips_by_mac[mac] - {find_ip_of_mac(packets, mac)}
    for ip, macs in macs_by_ip.items():
        if len(macs) > 1:
            spoofer = max(macs, key=lambda mac: (mac in suspect_macs, macs[mac]))
            spoofed_ips_by_mac[spoofer].add(ip)
    return spoofed_ips_by_mac


def detect_arp_spoofing(packets: list[Packet], other_attacker_macs: set[str] | None = None) -> list[Attack]:
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
        for mac, spoofed_ips in find_arp_spoofers(packets, other_attacker_macs or set()).items()
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


def get_http_request(packet: Packet) -> str | None:
    """
    Retourne la requête HTTP en clair portée par un paquet, URL décodée (%27 -> '). Le trafic chiffré
    (HTTPS) n'est pas analysable : y chercher du SQL donnerait des alertes au hasard des octets chiffrés

    :return: texte de la requête, None si le paquet ne contient pas de requête HTTP
    """
    if not (packet.haslayer(TCP) and packet.haslayer(Raw)):
        return None
    payload = bytes(packet[Raw].load).decode("latin-1")
    if not payload.startswith(HTTP_METHODS):
        return None
    return unquote_plus(payload)


def detect_sql_injection(packets: list[Packet]) -> list[Attack]:
    """
    Injection SQL : l'attaquant glisse du SQL dans une requête HTTP (URL, formulaire) pour lire ou
    modifier la base de données du site. Une alerte par attaquant, avec sa première requête suspecte
    """
    attacks = {}  # IP de l'attaquant -> attaque
    for packet in packets:
        request = get_http_request(packet)
        source_ip = get_source_ip(packet)
        if request is None or source_ip in attacks or not SQL_INJECTION_PATTERN.search(request):
            continue
        request_line = request.splitlines()[0][:100]
        # !r échappe les caractères de contrôle envoyés par l'attaquant (pas de piège dans le terminal)
        attacks[source_ip] = Attack(
            attack_type="sql_injection",
            name="Injection SQL",
            protocol=get_protocol(packet),
            attacker_ip=source_ip,
            attacker_mac=get_source_mac(packet),
            details=f"requête HTTP vers {get_destination_ip(packet)} : {request_line!r}",
        )
    return list(attacks.values())


def find_flag(packets: list[Packet]) -> str | None:
    """
    Cherche le marqueur unique ESGI{...} dans le trafic, même encodé dans une URL (%7B -> {)

    :param packets: paquets capturés
    :return: le marqueur, None s'il n'est dans aucun paquet
    """
    for packet in packets:
        match = FLAG_PATTERN.search(unquote(bytes(packet).decode("latin-1")))
        if match:
            return match.group(0)
    return None


def detect_attacks(packets: list[Packet]) -> list[Attack]:
    """
    Cherche toutes les attaques connues dans les paquets capturés

    :param packets: paquets capturés
    :return: tentatives d'attaque trouvées, liste vide si tout va bien
    """
    ip_attacks = detect_syn_scan(packets) + detect_sql_injection(packets)
    # la MAC d'un attaquant déjà repéré (scan, injection) désigne l'usurpateur en cas de doute sur l'ARP
    other_attacker_macs = {attack.attacker_mac for attack in ip_attacks}
    return detect_arp_spoofing(packets, other_attacker_macs) + ip_attacks
