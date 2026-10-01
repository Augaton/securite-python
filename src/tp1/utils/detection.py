import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from urllib.parse import unquote_plus

from scapy.all import ARP, IP, TCP, Ether, IPv6, Packet, Raw

from src.tp1.utils.lib import HTTP_METHODS

UNKNOWN = "inconnue"
ETHERTYPE_IPV4 = 0x0800
ARP_WHO_HAS = 1
ARP_IS_AT = 2
SYN_SCAN_MIN_PORTS = 10
SQL_INJECTION_PATTERN = re.compile(
    r"""["']\s*(or|and)\s*["']?\w*["']?\s*="""  # ' OR '1'='1, ' AND 1=1, ' or ''='
    r"|\b(or|and)\s+\d+\s*=\s*\d+"  # OR 1=1 (champ numérique, sans guillemet)
    r"|\bunion\s+(all\s+)?select\b"  # UNION SELECT
    r"|;\s*(drop|delete|insert|update|select)\b"  # ; DROP TABLE
    r"""|["']\s*(--|#)(\s|&|$)|["']\s*/\*"""  # ' -- (fin de la vraie requête en commentaire)
    r"|\b(sleep|pg_sleep|benchmark)\s*\("  # injection à l'aveugle basée sur le temps
    r"|\binformation_schema\b",
    re.IGNORECASE,
)
# imprimable et borné : pas de codes de contrôle dans les logs, pas de recherche qui s'emballe
FLAG_PATTERN = re.compile(r"ESGI\{[\x21-\x7c\x7e]{1,100}\}")


@dataclass(frozen=True)
class Attack:
    """
    Tentative d'attaque repérée dans le trafic
    """

    attack_type: str
    name: str
    protocol: str
    attacker_ip: str
    attacker_mac: str
    details: str

    def get_attacker(self) -> str:
        """
        Adresse qui identifie l'attaquant : sa MAC pour l'ARP, son IP sinon
        """
        return self.attacker_mac if self.protocol == "ARP" else self.attacker_ip

    def describe(self) -> str:
        """
        Décrit l'attaque en une ligne
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


def is_ipv4_arp(arp: ARP) -> bool:
    """
    Vérifie que c'est un ARP IPv4 sur Ethernet : dans un ARP malformé les adresses sont des octets bruts
    """
    # hwlen et plen valent None dans un paquet construit à la main
    return (
        arp.hwtype == 1 and arp.ptype == ETHERTYPE_IPV4 and arp.hwlen in (None, 6) and arp.plen in (None, 4)
    )


def get_http_request(packet: Packet) -> str | None:
    """
    Retourne la requête HTTP en clair d'un paquet, URL décodée (le HTTPS chiffré n'est pas analysable)

    :return: texte de la requête, None si le paquet ne contient pas de requête HTTP
    """
    if not packet.haslayer(Raw):
        return None
    payload = bytes(packet[Raw].load)
    if not payload.startswith(HTTP_METHODS):
        return None
    return unquote_plus(payload.decode("latin-1"))


def build_sql_injection(packet: Packet, source_ip: str, request: str) -> Attack:
    """
    Décrit l'injection SQL portée par la requête HTTP d'un paquet

    :return: l'attaque, avec la première ligne de la requête
    """
    request_line = request.splitlines()[0][:100]
    # !r échappe les caractères de contrôle envoyés par l'attaquant avant qu'ils arrivent au terminal
    return Attack(
        attack_type="sql_injection",
        name="Injection SQL",
        protocol="HTTP",
        attacker_ip=source_ip,
        attacker_mac=get_source_mac(packet),
        details=f"requête HTTP vers {get_destination_ip(packet)} : {request_line!r}",
    )


def find_flag(request: str) -> str | None:
    """
    Cherche le marqueur ESGI{...} dans une requête HTTP déjà décodée

    :return: le marqueur, None si la requête n'en contient pas
    """
    match = FLAG_PATTERN.search(request)
    return match.group(0) if match else None


class TrafficAnalyzer:
    """
    Analyse le trafic paquet par paquet, sans garder les paquets
    """

    def __init__(self) -> None:
        self.arp_macs_by_ip = defaultdict(dict)  # {IP : {MAC : rang d'arrivée}}
        self.arp_requests_waiting = Counter()  # {IP demandée : nombre de "who-has" sans réponse}
        self.unsolicited_arp_replies = defaultdict(Counter)  # {IP annoncée : {MAC : nombre}}
        # vraie IP d'une MAC, vue dans son trafic IP : en ARP spoofing l'IP annoncée est celle de la victime
        self.ip_by_mac = {}
        self.syn_ports_by_ip = defaultdict(set)
        self.syn_targets_by_ip = defaultdict(set)
        self.syn_mac_by_ip = {}
        self.sql_injections = {}
        self.flag = None

    def add_packet(self, packet: Packet) -> None:
        """
        Prend en compte un paquet capturé
        """
        source_ip = get_source_ip(packet)
        if source_ip != UNKNOWN:
            self.ip_by_mac.setdefault(get_source_mac(packet), source_ip)
        if packet.haslayer(ARP):
            self.add_arp(packet[ARP])
        if packet.haslayer(TCP):
            self.add_tcp(packet, source_ip)

    def add_arp(self, arp: ARP) -> None:
        """
        Note l'annonce ARP "l'IP psrc est à la MAC hwsrc" (0.0.0.0 : machine sans IP, ignorée), et si
        c'est une réponse que personne n'a demandée
        """
        if not is_ipv4_arp(arp):
            return
        if arp.op == ARP_WHO_HAS:
            self.arp_requests_waiting[arp.pdst] += 1
        elif arp.op == ARP_IS_AT:
            self.add_arp_reply(arp)
        if arp.psrc != "0.0.0.0":
            macs = self.arp_macs_by_ip[arp.psrc]
            macs.setdefault(arp.hwsrc, len(macs))

    def add_arp_reply(self, arp: ARP) -> None:
        """
        Une réponse ARP répond à une demande pour son IP pas encore servie, sinon elle est non sollicitée
        """
        if self.arp_requests_waiting[arp.psrc] > 0:
            self.arp_requests_waiting[arp.psrc] -= 1
        else:
            self.unsolicited_arp_replies[arp.psrc][arp.hwsrc] += 1

    def add_tcp(self, packet: Packet, source_ip: str) -> None:
        """
        Note les SYN seuls (scan), les injections SQL des requêtes HTTP et leur marqueur
        """
        if packet[TCP].flags == "S":
            self.syn_ports_by_ip[source_ip].add(packet[TCP].dport)
            self.syn_targets_by_ip[source_ip].add(get_destination_ip(packet))
            self.syn_mac_by_ip.setdefault(source_ip, get_source_mac(packet))
        # pas de elif : un paquet fabriqué avec scapy est un SYN par défaut, même s'il porte une requête
        request = get_http_request(packet)
        if request is None or not SQL_INJECTION_PATTERN.search(request):
            return
        if source_ip not in self.sql_injections:
            self.sql_injections[source_ip] = build_sql_injection(packet, source_ip, request)
        # le marqueur est celui de l'injection : la capture contient aussi un faux marqueur (leurre) ailleurs
        if self.flag is None:
            self.flag = find_flag(request)

    def get_attacks(self) -> list[Attack]:
        """
        Retourne toutes les tentatives d'attaque trouvées
        """
        return (
            self.get_arp_spoofing_attacks() + self.get_syn_scan_attacks() + self.get_sql_injection_attacks()
        )

    def find_ip_owner(self, ip: str) -> str:
        """
        Retourne la vraie MAC d'une IP annoncée par plusieurs MAC : celle qui envoie le moins de réponses
        ARP non sollicitées (l'usurpateur en envoie en boucle), à égalité la première vue (comme arpwatch)
        """
        macs = self.arp_macs_by_ip[ip]
        unsolicited_replies = self.unsolicited_arp_replies[ip]
        return min(macs, key=lambda mac: (unsolicited_replies[mac], macs[mac]))

    def find_arp_spoofers(self) -> dict[str, set[str]]:
        """
        Retourne les MAC qui usurpent des IP, avec les IP usurpées : les MAC qui annoncent une IP à la
        place de sa vraie MAC. Une MAC qui annonce plusieurs IP n'est pas suspecte en soi (dans une
        capture générée, plusieurs machines partagent une MAC)
        """
        spoofed_ips_by_mac = defaultdict(set)
        for ip, macs in self.arp_macs_by_ip.items():
            if len(macs) < 2:
                continue
            owner = self.find_ip_owner(ip)
            for mac in macs:
                if mac != owner:
                    spoofed_ips_by_mac[mac].add(ip)
        return spoofed_ips_by_mac

    def count_unsolicited_replies(self, mac: str, ips: set[str]) -> int:
        """
        Retourne le nombre de réponses ARP non sollicitées d'une MAC pour des IP
        """
        return sum(self.unsolicited_arp_replies[ip][mac] for ip in ips)

    def get_arp_spoofing_attacks(self) -> list[Attack]:
        """
        Retourne les ARP spoofing : de fausses annonces ARP pour recevoir le trafic d'une autre machine
        """
        return [
            Attack(
                attack_type="arp_spoofing",
                name="ARP spoofing",
                protocol="ARP",
                attacker_ip=self.ip_by_mac.get(mac, UNKNOWN),
                attacker_mac=mac,
                details=(
                    f"se fait passer pour {', '.join(sorted(spoofed_ips))} "
                    f"({self.count_unsolicited_replies(mac, spoofed_ips)} réponse(s) ARP non sollicitée(s))"
                ),
            )
            for mac, spoofed_ips in self.find_arp_spoofers().items()
        ]

    def get_syn_scan_attacks(self) -> list[Attack]:
        """
        Retourne les scans SYN : des SYN seuls vers au moins SYN_SCAN_MIN_PORTS ports différents
        """
        return [
            Attack(
                attack_type="port_scan",
                name="Scan SYN",
                protocol="TCP",
                attacker_ip=ip,
                attacker_mac=self.syn_mac_by_ip[ip],
                details=f"{len(ports)} ports visés sur {', '.join(sorted(self.syn_targets_by_ip[ip]))}",
            )
            for ip, ports in self.syn_ports_by_ip.items()
            if len(ports) >= SYN_SCAN_MIN_PORTS
        ]

    def get_sql_injection_attacks(self) -> list[Attack]:
        """
        Retourne les injections SQL : une par attaquant, avec sa première requête suspecte
        """
        return list(self.sql_injections.values())


def analyse_packets(packets: list[Packet]) -> TrafficAnalyzer:
    """
    Analyse des paquets déjà capturés

    :param packets: paquets à analyser
    :return: l'analyseur, avec les attaques (get_attacks) et le marqueur (flag) trouvés
    """
    analyzer = TrafficAnalyzer()
    for packet in packets:
        analyzer.add_packet(packet)
    return analyzer
