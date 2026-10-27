from collections import Counter

from scapy.all import Packet, conf, sniff

from src.tp1.utils.config import logger
from src.tp1.utils.detection import TrafficAnalyzer
from src.tp1.utils.lib import choose_interface, recup_lst_protos

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

    def ouvrir_socket_ecoute(self) -> None:
        """Ouvre le socket de capture : la seule étape qui a besoin des droits root."""
        if self.pcap_file is None:
            self.listen_socket = conf.L2listen(iface=self.interface)

    def lire_fichier_pcap(self) -> None:
        sniff(offline=self.pcap_file, prn=self.ajout_pkt, store=False)
        logger.info(f"{self.recup_nb_pkt()} paquets lus dans {self.pcap_file}")

    def ecouter_interface(self) -> None:
        if self.listen_socket is None:
            self.ouvrir_socket_ecoute()
        logger.info(
            f"Capture sur {self.interface} pendant {self.timeout} secondes (Ctrl+C pour arrêter avant)"
        )
        try:
            # sniff s'arrête proprement sur Ctrl+C, les paquets déjà reçus restent comptés
            sniff(opened_socket=self.listen_socket, timeout=self.timeout, prn=self.ajout_pkt, store=False)
        finally:
            self.listen_socket.close()
            self.listen_socket = None
        logger.info(f"{self.recup_nb_pkt()} paquets capturés")

    def capture_traffic(self) -> None:
        if self.pcap_file is not None:
            self.lire_fichier_pcap()
        else:
            self.ecouter_interface()

    def ajout_pkt(self, packet: Packet) -> None:
        self.packet_count += 1
        self.protocol_counts.update(recup_lst_protos(packet))
        self.analyzer.ajout_pkt(packet)

    def recup_nb_pkt(self) -> int:
        return self.packet_count

    def recup_source(self) -> str:
        return f"fichier {self.pcap_file}" if self.pcap_file is not None else f"interface {self.interface}"

    def sort_network_protocols(self) -> dict:
        """Protocoles capturés, du plus utilisé au moins utilisé."""
        all_protocols = self.get_all_protocols()
        return dict(sorted(all_protocols.items(), key=lambda item: item[1], reverse=True))

    def get_all_protocols(self) -> dict:
        return dict(self.protocol_counts)

    def log_protos(self) -> None:
        for proto, nb in self.protocols.items():
            logger.info(f"{proto} : {nb} paquets")

    def log_attaques(self) -> None:
        for attaque in self.attacks:
            logger.warning(f"Tentative d'attaque : {attaque.decrire()}")
        if not self.attacks:
            logger.info("Aucune attaque détectée, tout va bien")

    def log_flag(self) -> None:
        if self.flag is not None:
            logger.info(f"Marqueur trouvé : {self.flag}")

    def analyse(self) -> None:
        """Trie les protocoles, relève les attaques et le marqueur, puis construit le résumé."""
        self.protocols = self.sort_network_protocols()
        self.log_protos()
        self.attacks = self.analyzer.recup_attaques()
        self.log_attaques()
        self.flag = self.analyzer.recup_flag()
        self.log_flag()
        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        return self.summary

    def _gen_summary(self) -> str:
        if self.packet_count == 0:
            return f"Aucun paquet capturé ({self.recup_source()})."

        proto_top = next(iter(self.protocols))
        summary = (
            f"{self.packet_count} paquets ont été analysés ({self.recup_source()}). "
            f"Le protocole le plus utilisé est {proto_top} avec {self.protocols[proto_top]} paquets. "
        )
        return summary + self._gen_resume_attaques()

    def _gen_resume_attaques(self) -> str:
        if not self.attacks:
            return "Aucune attaque détectée, tout va bien."
        noms_attaques = ", ".join(attaque.name for attaque in self.attacks)
        return f"{len(self.attacks)} tentative(s) d'attaque détectée(s) : {noms_attaques}."
