from collections import Counter

from scapy.all import Packet, conf, sniff

from src.tp1.utils.config import logger
from src.tp1.utils.detection import TrafficAnalyzer
from src.tp1.utils.lib import choose_interface, get_protocol

TIMEOUT = 60


class Capture:
    def __init__(self, pcap_file: str | None = None, timeout: int = TIMEOUT) -> None:
        self.pcap_file = pcap_file
        self.timeout = timeout
        self.interface = choose_interface() if pcap_file is None else ""
        self.listen_socket = None
        self.protocol_counts = Counter()
        self.analyzer = TrafficAnalyzer()
        self.protocols = {}
        self.attacks = []
        self.flag = None
        self.summary = ""

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
        self.protocol_counts[get_protocol(packet)] += 1
        self.analyzer.add_packet(packet)

    def get_packet_count(self) -> int:
        """
        Retourne le nombre de paquets capturés
        """
        return sum(self.protocol_counts.values())

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
