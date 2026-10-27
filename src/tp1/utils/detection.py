import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from urllib.parse import unquote, unquote_plus

from scapy.all import ARP, IP, TCP, Ether, IPv6, Packet, Raw

from src.tp1.utils.lib import recup_proto_principal

UNKNOWN = "inconnue"
ETHERTYPE_IPV4 = 0x0800
SYN_SCAN_MIN_PORTS = 10
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"PATCH ", b"DELETE ", b"HEAD ", b"OPTIONS ")
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
    """Tentative d'attaque repérée dans le trafic."""

    attack_type: str
    name: str
    protocol: str
    attacker_ip: str
    attacker_mac: str
    details: str

    def recup_attaquant(self) -> str:
        """Identifiant de l'attaquant : sa MAC pour l'ARP, son IP sinon. Toutes les trames IP peuvent
        porter la même MAC (celle de la machine qui a fabriqué le pcap) : seule l'IP les distingue."""
        return self.attacker_mac if self.attack_type == "arp_spoofing" else self.attacker_ip

    def decrire(self) -> str:
        return (
            f"{self.name} ({self.protocol}) depuis {self.attacker_ip} / {self.attacker_mac} : {self.details}"
        )


def recup_couche_ip(packet: Packet) -> Packet | None:
    for couche_ip in (IP, IPv6):
        if packet.haslayer(couche_ip):
            return packet[couche_ip]
    return None


def recup_mac_src(packet: Packet) -> str:
    return packet[Ether].src if packet.haslayer(Ether) else UNKNOWN


def recup_ip_src(packet: Packet) -> str:
    couche_ip = recup_couche_ip(packet)
    return couche_ip.src if couche_ip is not None else UNKNOWN


def recup_ip_dst(packet: Packet) -> str:
    couche_ip = recup_couche_ip(packet)
    return couche_ip.dst if couche_ip is not None else UNKNOWN


def verif_arp_ipv4(arp: ARP) -> bool:
    """ARP IPv4 sur Ethernet : dans un ARP malformé les adresses sont des octets bruts."""
    # hwlen et plen valent None dans un paquet construit à la main
    return (
        arp.hwtype == 1 and arp.ptype == ETHERTYPE_IPV4 and arp.hwlen in (None, 6) and arp.plen in (None, 4)
    )


def recup_req_http(packet: Packet) -> str | None:
    """Requête HTTP en clair d'un paquet, URL décodée, ou None (le HTTPS chiffré n'est pas analysable)."""
    if not packet.haslayer(Raw):
        return None
    payload = bytes(packet[Raw].load)
    if not payload.startswith(HTTP_METHODS):
        return None
    return unquote_plus(payload.decode("latin-1"))


def verif_sqli(req: str) -> bool:
    return SQL_INJECTION_PATTERN.search(req) is not None


def constr_attaque_sqli(packet: Packet, ip_src: str, req: str) -> Attack:
    ligne_req = req.splitlines()[0][:100]
    # !r échappe les caractères de contrôle envoyés par l'attaquant avant qu'ils arrivent au terminal
    return Attack(
        attack_type="sql_injection",
        name="Injection SQL",
        protocol=recup_proto_principal(packet),
        attacker_ip=ip_src,
        attacker_mac=recup_mac_src(packet),
        details=f"requête HTTP vers {recup_ip_dst(packet)} : {ligne_req!r}",
    )


def chercher_injection_sql(packet: Packet, ip_src: str) -> Attack | None:
    req = recup_req_http(packet)
    if req is None or not verif_sqli(req):
        return None
    return constr_attaque_sqli(packet, ip_src, req)


def chercher_flag_pkt(packet: Packet) -> str | None:
    # original = octets reçus, bytes(packet) reconstruirait tout le paquet (beaucoup plus lent)
    pkt_brut = packet.original or bytes(packet)
    if b"ESGI" not in pkt_brut:
        return None
    match = FLAG_PATTERN.search(unquote(pkt_brut.decode("latin-1")))
    return match.group(0) if match else None


def choisir_usurpateur(nb_rep_par_mac: Counter, macs_suspectes: set[str]) -> str:
    """MAC accusée pour une IP annoncée par plusieurs MAC : la suspecte, sinon celle qui répond le plus."""
    # reversed : max garde le premier ex aequo rencontré, donc ici le dernier arrivé
    return max(reversed(nb_rep_par_mac), key=lambda mac: (mac in macs_suspectes, nb_rep_par_mac[mac]))


class TrafficAnalyzer:
    """Analyse le trafic paquet par paquet, sans garder les paquets."""

    def __init__(self) -> None:
        self.arp_replies_by_ip = defaultdict(Counter)  # {IP : {MAC : nombre de réponses}}, ordre d'arrivée
        self.arp_ips_by_mac = defaultdict(set)
        # vraie IP d'une MAC, vue dans son trafic IP : en ARP spoofing l'IP annoncée est celle de la victime
        self.ip_by_mac = {}
        self.syn_ports_by_ip = defaultdict(set)
        self.syn_targets_by_ip = defaultdict(set)
        self.syn_mac_by_ip = {}
        self.sql_injections = {}
        self.flag_by_ip = {}  # premier marqueur envoyé par chaque IP source, dans l'ordre d'arrivée

    def ajout_pkt(self, packet: Packet) -> None:
        ip_src = recup_ip_src(packet)
        if ip_src != UNKNOWN:
            self.ip_by_mac.setdefault(recup_mac_src(packet), ip_src)
        if packet.haslayer(ARP):
            self.ajout_arp(packet[ARP])
        if packet.haslayer(TCP):
            self.ajout_tcp(packet, ip_src)
        self.ajout_flag(packet, ip_src)

    def ajout_arp(self, arp: ARP) -> None:
        """Note la réponse ARP "l'IP psrc est à la MAC hwsrc" (0.0.0.0 : machine sans IP, ignorée).
        L'usurpation passe par des réponses ; une requête ne fait que demander une adresse, et son
        hwsrc peut être celle de la machine qui a fabriqué la trame, pas celle de l'émetteur."""
        if verif_arp_ipv4(arp) and arp.op == 2 and arp.psrc != "0.0.0.0":
            self.arp_replies_by_ip[arp.psrc][arp.hwsrc] += 1
            self.arp_ips_by_mac[arp.hwsrc].add(arp.psrc)

    def ajout_tcp(self, packet: Packet, ip_src: str) -> None:
        if packet[TCP].flags == "S":
            self.ajout_syn(packet, ip_src)
        # pas de elif : un paquet fabriqué avec scapy est un SYN par défaut, même s'il porte une requête
        self.ajout_sqli(packet, ip_src)

    def ajout_syn(self, packet: Packet, ip_src: str) -> None:
        self.syn_ports_by_ip[ip_src].add(packet[TCP].dport)
        self.syn_targets_by_ip[ip_src].add(recup_ip_dst(packet))
        self.syn_mac_by_ip.setdefault(ip_src, recup_mac_src(packet))

    def ajout_sqli(self, packet: Packet, ip_src: str) -> None:
        if ip_src in self.sql_injections:
            return
        injection = chercher_injection_sql(packet, ip_src)
        if injection is not None:
            self.sql_injections[ip_src] = injection

    def ajout_flag(self, packet: Packet, ip_src: str) -> None:
        if ip_src in self.flag_by_ip:
            return
        flag = chercher_flag_pkt(packet)
        if flag is not None:
            self.flag_by_ip[ip_src] = flag

    def recup_flag(self) -> str | None:
        """Le marqueur envoyé par l'auteur d'une injection SQL, sinon le premier vu : un marqueur
        envoyé plus tôt par une autre machine peut être un leurre."""
        for ip_attaquant in self.sql_injections:
            if ip_attaquant in self.flag_by_ip:
                return self.flag_by_ip[ip_attaquant]
        return next(iter(self.flag_by_ip.values()), None)

    def recup_attaques(self) -> list[Attack]:
        attaques_ip = self.recup_attaques_scan_syn() + self.recup_attaques_sqli()
        macs_autres_attaques = {attaque.attacker_mac for attaque in attaques_ip}
        return self.recup_attaques_arp(macs_autres_attaques) + attaques_ip

    def recup_macs_plusieurs_ip(self) -> set[str]:
        return {mac for mac, ips in self.arp_ips_by_mac.items() if len(ips) > 1}

    def trouver_usurpateurs_arp(self, macs_autres_attaques: set[str]) -> dict[str, set[str]]:
        """
        Retourne les MAC qui usurpent des IP, avec les IP usurpées :
        - une MAC qui annonce plusieurs IP les usurpe toutes
        - pour une IP annoncée par plusieurs MAC, on accuse celle déjà suspecte (plusieurs IP, ou source
          d'une autre attaque), sinon celle qui envoie le plus de réponses : l'usurpateur inonde ses
          victimes, la vraie machine ne répond qu'à leurs requêtes ; à égalité, la dernière arrivée
        """
        macs_plusieurs_ip = self.recup_macs_plusieurs_ip()
        macs_suspectes = macs_plusieurs_ip | macs_autres_attaques
        ips_usurpees_par_mac = defaultdict(set)
        for mac in macs_plusieurs_ip:
            ips_usurpees_par_mac[mac] |= self.arp_ips_by_mac[mac] - {self.ip_by_mac.get(mac)}
        for ip, nb_rep_par_mac in self.arp_replies_by_ip.items():
            if len(nb_rep_par_mac) > 1:
                ips_usurpees_par_mac[choisir_usurpateur(nb_rep_par_mac, macs_suspectes)].add(ip)
        return ips_usurpees_par_mac

    def recup_attaques_arp(self, macs_autres_attaques: set[str] | None = None) -> list[Attack]:
        return [
            Attack(
                attack_type="arp_spoofing",
                name="ARP spoofing",
                protocol="ARP",
                attacker_ip=self.ip_by_mac.get(mac, UNKNOWN),
                attacker_mac=mac,
                details=f"se fait passer pour {', '.join(sorted(ips_usurpees))}",
            )
            for mac, ips_usurpees in self.trouver_usurpateurs_arp(macs_autres_attaques or set()).items()
        ]

    def recup_attaques_scan_syn(self) -> list[Attack]:
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

    def recup_attaques_sqli(self) -> list[Attack]:
        return list(self.sql_injections.values())


def analyser_lst_pkt(packets: list[Packet]) -> TrafficAnalyzer:
    analyzer = TrafficAnalyzer()
    for packet in packets:
        analyzer.ajout_pkt(packet)
    return analyzer
