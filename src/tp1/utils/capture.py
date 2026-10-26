from collections import Counter

from scapy.all import Packet, conf, sniff

from src.tp1.utils.config import logger
from src.tp1.utils.detection import TrafficAnalyzer
from src.tp1.utils.lib import choose_interface, get_protocols

TIMEOUT = 60


class Capture:
    def __init__(self, pcap_file: str | None = None, timeout: int = TIMEOUT) -> None:
        self.pcap_file = pcap_file
        self.timeout = timeout
        self.interface = choose_interface() if pcap_file is None else ""
        self.listen_socket = None
        self.packet_count = 0
        self.protocol_counts = Counter()
        self.analyzer = TrafficAnalyzer()
        self.protocols = {}
        self.attacks = []
        self.flag = None
        self.summary = ""

    def open_socket(self) -> None:
        """Ouvre le socket de capture : la seule étape qui a besoin des droits root."""
        if self.pcap_file is None:
            self.listen_socket = conf.L2listen(iface=self.interface)

    def capture_traffic(self) -> None:
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
        self.packet_count += 1
        self.protocol_counts.update(get_protocols(packet))
        self.analyzer.add_packet(packet)

    def get_packet_count(self) -> int:
        return self.packet_count

    def get_source(self) -> str:
        return f"fichier {self.pcap_file}" if self.pcap_file is not None else f"interface {self.interface}"

    def sort_network_protocols(self) -> dict:
        """Protocoles capturés, du plus utilisé au moins utilisé."""
        all_protocols = self.get_all_protocols()
        return dict(sorted(all_protocols.items(), key=lambda item: item[1], reverse=True))

    def get_all_protocols(self) -> dict:
        return dict(self.protocol_counts)

    def analyse(self) -> None:
        """Trie les protocoles, relève les attaques et le marqueur, puis construit le résumé."""
        self.protocols = self.sort_network_protocols()
        for protocol, count in self.protocols.items():
            logger.info(f"{protocol} : {count} paquets")

        self.attacks = self.analyzer.get_attacks()
        for attack in self.attacks:
            logger.warning(f"Tentative d'attaque : {attack.describe()}")
        if not self.attacks:
            logger.info("Aucune attaque détectée, tout va bien")

        self.flag = self.analyzer.get_flag()
        if self.flag is not None:
            logger.info(f"Marqueur trouvé : {self.flag}")

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        return self.summary

    def _gen_summary(self) -> str:
        if self.packet_count == 0:
            return f"Aucun paquet capturé ({self.get_source()})."

        most_used = next(iter(self.protocols))
        summary = (
            f"{self.packet_count} paquets ont été analysés ({self.get_source()}). "
            f"Le protocole le plus utilisé est {most_used} avec {self.protocols[most_used]} paquets. "
        )
        return summary + self._gen_attacks_summary()

    def _gen_attacks_summary(self) -> str:
        if not self.attacks:
            return "Aucune attaque détectée, tout va bien."
        attack_names = ", ".join(attack.name for attack in self.attacks)
        return f"{len(self.attacks)} tentative(s) d'attaque détectée(s) : {attack_names}."
