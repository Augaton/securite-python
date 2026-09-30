from scapy.all import rdpcap, sniff

from src.tp1.utils.config import logger
from src.tp1.utils.detection import detect_attacks, find_flag
from src.tp1.utils.lib import choose_interface, get_protocol

# Durée de la capture par défaut, sans limite de paquets : le PCAP rejoué par le conteneur attaquant
# peut dépasser la centaine de paquets. Ctrl+C arrête la capture avant la fin.
TIMEOUT = 60


class Capture:
    def __init__(self, pcap_file: str | None = None, timeout: int = TIMEOUT) -> None:
        self.pcap_file = pcap_file  # fichier à analyser au lieu d'écouter le réseau
        self.timeout = timeout
        self.interface = choose_interface() if pcap_file is None else ""
        self.packets = []
        self.protocols = {}  # {protocole: nombre de paquets}
        self.attacks = []  # tentatives d'attaque trouvées par analyse()
        self.flag = None  # marqueur ESGI{...} trouvé dans le trafic
        self.summary = ""

    def capture_traffic(self) -> None:
        """
        Capture network traffic from an interface (ou lit les paquets du fichier pcap)
        """
        if self.pcap_file is not None:
            self.packets = rdpcap(self.pcap_file)
            logger.info(f"{len(self.packets)} paquets lus dans {self.pcap_file}")
            return
        logger.info(
            f"Capture sur {self.interface} pendant {self.timeout} secondes (Ctrl+C pour arrêter avant)"
        )
        # sniff s'arrête proprement sur Ctrl+C et renvoie les paquets déjà capturés
        self.packets = sniff(iface=self.interface, timeout=self.timeout)
        logger.info(f"{len(self.packets)} paquets capturés")

    def get_source(self) -> str:
        """
        Retourne d'où viennent les paquets : l'interface écoutée ou le fichier pcap lu
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
        protocols = {}
        for packet in self.packets:
            protocol = get_protocol(packet)
            if protocol in protocols:
                protocols[protocol] += 1
            else:
                protocols[protocol] = 1
        return protocols

    def analyse(self) -> None:
        """
        Analyse all captured data and return statement
        Si un trafic est illégitime (exemple : Injection SQL, ARP Spoofing, etc)
        a. Noter la tentative d'attaque.
        b. Relever le protocole ainsi que l'adresse réseau/physique de l'attaquant.
        c. (FACULTATIF) Opérer le blocage de la machine attaquante (pas fait : une fausse alerte
           couperait une machine légitime, la passerelle par exemple)
        Sinon afficher que tout va bien
        """
        self.protocols = self.sort_network_protocols()
        for protocol, count in self.protocols.items():
            logger.info(f"{protocol} : {count} paquets")

        self.attacks = detect_attacks(self.packets)
        for attack in self.attacks:
            logger.warning(f"Tentative d'attaque : {attack.describe()}")
        if not self.attacks:
            logger.info("Aucune attaque détectée, tout va bien")

        self.flag = find_flag(self.packets)
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

        # le dictionnaire est trié donc le premier protocole est le plus utilisé
        most_used = list(self.protocols)[0]
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
