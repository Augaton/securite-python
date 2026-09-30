import re
from collections import defaultdict
from dataclasses import dataclass
from urllib.parse import unquote, unquote_plus

from scapy.all import ARP, IP, TCP, Ether, IPv6, Packet, Raw

from src.tp1.utils.lib import get_protocol

UNKNOWN = "inconnue"
# Nombre de ports différents visés par des SYN à partir duquel on considère que c'est un scan
SYN_SCAN_MIN_PORTS = 10
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"PATCH ", b"DELETE ", b"HEAD ", b"OPTIONS ")
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
# Marqueur unique glissé par le conteneur attaquant dans son injection SQL. Seulement des caractères
# imprimables (un faux marqueur avec des séquences d'échappement piloterait le terminal des logs) et
# 100 au plus (sans limite, un paquet rempli de "ESGI{" bloquait la recherche plusieurs secondes)
FLAG_PATTERN = re.compile(r"ESGI\{[\x21-\x7c\x7e]{1,100}\}")


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


def is_ipv4_arp(arp: ARP) -> bool:
    """
    Vérifie que c'est un ARP classique (IPv4 sur Ethernet). Dans un ARP malformé, scapy donne les
    adresses en octets bruts au lieu de texte, ce qui faisait planter l'analyse : un seul paquet
    bizarre envoyé par un attaquant suffisait à couper l'outil
    """
    # hwlen et plen valent None dans un paquet construit à la main (calculés à l'envoi)
    return arp.hwtype == 1 and arp.ptype == 0x0800 and arp.hwlen in (None, 6) and arp.plen in (None, 4)


def get_http_request(packet: Packet) -> str | None:
    """
    Retourne la requête HTTP en clair portée par un paquet, URL décodée (%27 -> '). Le trafic chiffré
    (HTTPS) n'est pas analysable : y chercher du SQL donnerait des alertes au hasard des octets chiffrés

    :return: texte de la requête, None si le paquet ne contient pas de requête HTTP
    """
    if not packet.haslayer(Raw):
        return None
    payload = bytes(packet[Raw].load)
    # le début est testé en octets avant de décoder : la plupart des paquets (HTTPS...) s'arrêtent là
    if not payload.startswith(HTTP_METHODS):
        return None
    return unquote_plus(payload.decode("latin-1"))


def find_sql_injection(packet: Packet, source_ip: str) -> Attack | None:
    """
    Injection SQL : l'attaquant glisse du SQL dans une requête HTTP (URL, formulaire) pour lire ou
    modifier la base de données du site

    :return: l'attaque si la requête HTTP du paquet contient une injection, None sinon
    """
    request = get_http_request(packet)
    if request is None or not SQL_INJECTION_PATTERN.search(request):
        return None
    request_line = request.splitlines()[0][:100]
    # !r échappe les caractères de contrôle envoyés par l'attaquant (pas de piège dans le terminal)
    return Attack(
        attack_type="sql_injection",
        name="Injection SQL",
        protocol=get_protocol(packet),
        attacker_ip=source_ip,
        attacker_mac=get_source_mac(packet),
        details=f"requête HTTP vers {get_destination_ip(packet)} : {request_line!r}",
    )


def search_flag(packet: Packet) -> str | None:
    """
    Cherche le marqueur unique ESGI{...} dans un paquet, même encodé dans une URL (%7B -> {)

    :return: le marqueur, None s'il n'est pas dans le paquet
    """
    # octets reçus tels quels (original) : bytes(packet) reconstruirait tout le paquet, bien plus lent
    raw_packet = packet.original or bytes(packet)
    if b"ESGI" not in raw_packet:
        return None
    match = FLAG_PATTERN.search(unquote(raw_packet.decode("latin-1")))
    return match.group(0) if match else None


class TrafficAnalyzer:
    """
    Analyse le trafic paquet par paquet : chaque paquet n'est parcouru qu'une fois, et on ne garde que
    ce qu'il faut pour détecter les attaques (des adresses et des ports), pas les paquets eux-mêmes
    """

    def __init__(self) -> None:
        self.arp_macs_by_ip = defaultdict(dict)  # IP annoncée en ARP -> {MAC : rang d'arrivée}
        self.arp_ips_by_mac = defaultdict(set)  # MAC -> IP qu'elle annonce en ARP
        self.ip_by_mac = {}  # MAC -> première IP vue dans son propre trafic IP
        self.syn_ports_by_ip = defaultdict(set)  # IP source -> ports visés par des SYN seuls
        self.syn_targets_by_ip = defaultdict(set)  # IP source -> machines visées par ces SYN
        self.syn_mac_by_ip = {}  # IP source des SYN -> sa MAC
        self.sql_injections = {}  # IP de l'attaquant -> sa première injection SQL
        self.flag = None  # premier marqueur ESGI{...} trouvé

    def add_packet(self, packet: Packet) -> None:
        """
        Prend en compte un paquet capturé
        """
        source_ip = get_source_ip(packet)
        if source_ip != UNKNOWN:
            # en ARP spoofing l'IP annoncée est celle de la victime : la vraie IP de l'attaquant est
            # celle de son propre trafic IP
            self.ip_by_mac.setdefault(get_source_mac(packet), source_ip)
        if packet.haslayer(ARP):
            self.add_arp(packet[ARP])
        if packet.haslayer(TCP):
            self.add_tcp(packet, source_ip)
        if self.flag is None:
            self.flag = search_flag(packet)

    def add_arp(self, arp: ARP) -> None:
        """
        Note l'annonce ARP "l'IP psrc est à la MAC hwsrc" (0.0.0.0 = machine sans IP, ignorée)
        """
        if is_ipv4_arp(arp) and arp.psrc != "0.0.0.0":
            macs = self.arp_macs_by_ip[arp.psrc]
            macs.setdefault(arp.hwsrc, len(macs))
            self.arp_ips_by_mac[arp.hwsrc].add(arp.psrc)

    def add_tcp(self, packet: Packet, source_ip: str) -> None:
        """
        Note les SYN seuls (scan) et cherche une injection SQL dans les requêtes HTTP
        """
        if packet[TCP].flags == "S":
            self.syn_ports_by_ip[source_ip].add(packet[TCP].dport)
            self.syn_targets_by_ip[source_ip].add(get_destination_ip(packet))
            self.syn_mac_by_ip.setdefault(source_ip, get_source_mac(packet))
        # pas de elif : un paquet fabriqué avec scapy est un SYN par défaut, même s'il porte une requête
        if source_ip not in self.sql_injections:
            injection = find_sql_injection(packet, source_ip)
            if injection is not None:
                self.sql_injections[source_ip] = injection

    def get_attacks(self) -> list[Attack]:
        """
        Retourne toutes les tentatives d'attaque trouvées, liste vide si tout va bien
        """
        ip_attacks = self.get_syn_scan_attacks() + self.get_sql_injection_attacks()
        # la MAC d'un attaquant déjà repéré (scan, injection) désigne l'usurpateur en cas de doute sur l'ARP
        other_attacker_macs = {attack.attacker_mac for attack in ip_attacks}
        return self.get_arp_spoofing_attacks(other_attacker_macs) + ip_attacks

    def find_arp_spoofers(self, other_attacker_macs: set[str]) -> dict[str, set[str]]:
        """
        Retourne les MAC qui usurpent des IP, avec les IP usurpées. Une MAC usurpe :
        - toutes les IP qu'elle annonce si elle en annonce plusieurs (ex : passerelle + victime)
        - une IP déjà annoncée par une autre MAC. On accuse la MAC déjà suspecte (plusieurs IP annoncées,
          ou source d'une autre attaque), sinon la dernière arrivée : comme arpwatch, la première MAC vue
          pour une IP est la vraie. Le nombre d'annonces ne compte pas : la vraie passerelle peut en faire
          beaucoup plus que l'attaquant
        """
        several_ips_macs = {mac for mac, ips in self.arp_ips_by_mac.items() if len(ips) > 1}
        suspect_macs = several_ips_macs | other_attacker_macs
        spoofed_ips_by_mac = defaultdict(set)
        for mac in several_ips_macs:
            spoofed_ips_by_mac[mac] |= self.arp_ips_by_mac[mac] - {self.ip_by_mac.get(mac)}
        for ip, macs in self.arp_macs_by_ip.items():
            if len(macs) > 1:
                spoofer = max(macs, key=lambda mac: (mac in suspect_macs, macs[mac]))
                spoofed_ips_by_mac[spoofer].add(ip)
        return spoofed_ips_by_mac

    def get_arp_spoofing_attacks(self, other_attacker_macs: set[str] | None = None) -> list[Attack]:
        """
        ARP spoofing : l'attaquant envoie de fausses annonces ARP pour recevoir le trafic destiné à une
        autre machine (souvent la passerelle) et l'espionner ou le modifier (homme du milieu)
        """
        return [
            Attack(
                attack_type="arp_spoofing",
                name="ARP spoofing",
                protocol="ARP",
                attacker_ip=self.ip_by_mac.get(mac, UNKNOWN),
                attacker_mac=mac,
                details=f"se fait passer pour {', '.join(sorted(spoofed_ips))}",
            )
            for mac, spoofed_ips in self.find_arp_spoofers(other_attacker_macs or set()).items()
        ]

    def get_syn_scan_attacks(self) -> list[Attack]:
        """
        Scan SYN : l'attaquant envoie des demandes de connexion TCP (SYN seul, sans ACK) vers beaucoup
        de ports pour trouver les services ouverts, sans jamais terminer les connexions
        """
        return [
            Attack(
                attack_type="syn_scan",
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
        Retourne les injections SQL trouvées : une par attaquant, avec sa première requête suspecte
        """
        return list(self.sql_injections.values())


def analyse_packets(packets: list[Packet]) -> TrafficAnalyzer:
    """
    Analyse des paquets déjà capturés, en un seul passage

    :param packets: paquets à analyser
    :return: l'analyseur, avec les attaques (get_attacks) et le marqueur (flag) trouvés
    """
    analyzer = TrafficAnalyzer()
    for packet in packets:
        analyzer.add_packet(packet)
    return analyzer
