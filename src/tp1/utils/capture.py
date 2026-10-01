from collections import Counter

from scapy.all import Packet, conf, sniff
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

from src.tp1.utils.config import logger
from src.tp1.utils.detection import TrafficAnalyzer
from src.tp1.utils.lib import choose_interface

TIMEOUT = 60

LAYERS = (
    ("Ethernet", Ether),
    ("ARP", ARP),
    ("IP", IP),
    ("IPv6", IPv6),
    ("TCP", TCP),
    ("UDP", UDP),
    ("ICMP", ICMP),
    ("DNS", DNS),
)
HTTP_PREFIXES = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"HTTP/")


def get_protocols(packet: Packet) -> list[str]:
    """
    Retourne toutes les couches reconnues dans un paquet (un paquet HTTP compte aussi en TCP, IP, Ethernet)

    :param packet: paquet à examiner
    :return: noms des protocoles présents
    """
    protocols = [name for name, layer in LAYERS if packet.haslayer(layer)]
    if packet.haslayer(TCP) and (
        packet.haslayer(HTTPRequest)
        or packet.haslayer(HTTPResponse)
        or bytes(packet[TCP].payload).startswith(HTTP_PREFIXES)
    ):
        protocols.append("HTTP")
    return protocols

    def open_socket(self) -> None:
        """
        Ouvre le socket de capture : la seule étape qui a besoin des droits root
        """
        if self.pcap_file is None:
            self.listen_socket = conf.L2listen(iface=self.interface)

    def capture_traffic(self) -> None:
        """
        Capture network traffic from an interface (ou lit le fichier pcap)
        """
        if self.pcap_file is not None:
            sniff(offline=self.pcap_file, prn=self.add_packet, store=False)
            logger.info(f"{self.get_packet_count()} paquets lus dans {self.pcap_file}")
            return
        if self.listen_socket is None:
            self.open_socket()
        logger.info(
            f"Capture sur {self.interface} pendant {self.timeout} secondes (Ctrl+C pour arrêter avant)"
        )
        try:
            # sniff s'arrête proprement sur Ctrl+C, les paquets déjà reçus restent comptés
            sniff(opened_socket=self.listen_socket, timeout=self.timeout, prn=self.add_packet, store=False)
        finally:
            self.listen_socket.close()
            self.listen_socket = None
        logger.info(f"{self.get_packet_count()} paquets capturés")

    def add_packet(self, packet: Packet) -> None:
        """
        Compte et analyse un paquet dès qu'il arrive, sans le garder en mémoire
        """
        self.packet_count += 1
        self.protocol_counts.update(get_protocols(packet))
        self.analyzer.add_packet(packet)

    def get_packet_count(self) -> int:
        """
        Retourne le nombre de paquets capturés
        """
        return self.packet_count

    def get_source(self) -> str:
        """
        Retourne l'interface écoutée ou le fichier pcap lu
        """
        return f"fichier {self.pcap_file}" if self.pcap_file is not None else f"interface {self.interface}"

    def sort_network_protocols(self) -> dict:
        """
        Sort and return all captured network protocols (du plus utilisé au moins utilisé)
        """
        all_protocols = self.get_all_protocols()
        return dict(sorted(all_protocols.items(), key=lambda item: item[1], reverse=True))

    def get_all_protocols(self) -> dict:
        """
        Return all protocols captured with total packets number
        """
        return dict(self.protocol_counts)

    def analyse(self) -> None:
        """
        Analyse all captured data and return statement
        Si un trafic est illégitime (exemple : Injection SQL, ARP Spoofing, etc)
        a. Noter la tentative d'attaque.
        b. Relever le protocole ainsi que l'adresse réseau/physique de l'attaquant.
        c. (FACULTATIF) Opérer le blocage de la machine attaquante.
        Sinon afficher que tout va bien
        """
        self.protocols = self.sort_network_protocols()
        for protocol, count in self.protocols.items():
            logger.info(f"{protocol} : {count} paquets")

        self.attacks = self.analyzer.get_attacks()
        for attack in self.attacks:
            logger.warning(f"Tentative d'attaque : {attack.describe()}")
        if not self.attacks:
            logger.info("Aucune attaque détectée, tout va bien")

        self.flag = self.analyzer.flag
        if self.flag is not None:
            logger.info(f"Marqueur trouvé : {self.flag}")

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """
        Return summary
        :return:
        """
        return self.summary

    def _gen_summary(self) -> str:
        """
        Generate summary
        """
        total = sum(self.protocols.values())
        if total == 0:
            return f"Aucun paquet capturé ({self.get_source()})."

        most_used = next(iter(self.protocols))
        summary = (
            f"{total} paquets ont été analysés ({self.get_source()}). "
            f"Le protocole le plus utilisé est {most_used} avec {self.protocols[most_used]} paquets. "
        )
        return summary + self._gen_attacks_summary()

    def _gen_attacks_summary(self) -> str:
        """
        Génère la partie du résumé sur la légitimité du trafic
        """
        if not self.attacks:
            return "Aucune attaque détectée, tout va bien."
        attack_names = ", ".join(attack.name for attack in self.attacks)
        return f"{len(self.attacks)} tentative(s) d'attaque détectée(s) : {attack_names}."
